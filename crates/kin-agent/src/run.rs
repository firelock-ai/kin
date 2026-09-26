// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The agent loop.

use crate::belt::{self, Belt, Route};
use crate::context::{self, ContextMeter, CountSource};
use crate::mcp::{McpClient, McpError, McpTool, ToolOutcome};
use crate::parse::{self, Turn};
use crate::provider::{
    ChatRequest, Completion, PromptCount, Provider, ProviderError, RequestAccounting, Usage,
};
use crate::repeat;
use crate::transcript::{now_iso, TranscriptWriter};
use crate::{AgentConfig, ExitStatus, RunOutcome};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
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

Reach for mcp__kin__lexical_lookup when the question names an exact identifier, string, or \
symbol to find, or when mcp__kin__find_references or mcp__kin__trace_data_flow answered with \
an inconclusive verdict for the entity you asked about. Resolve the entity first as usual, \
then call mcp__kin__lexical_lookup with that bare token, not a sentence describing it: it \
matches stored graph fields literally. A hit there is lexical evidence, never a \
resolved reference, so mcp__kin__find_references stays the answer of record whenever it \
certifies.

When a Kin result is empty, read what Kin says about that emptiness. If it reports the \
absence cannot be trusted, the honest answer is that you do not know, and you should say \
what the gap is. Never turn an untrusted absence into a claim that something does not exist.

To change code, name the entity you are changing by its UUID, the id \
mcp__kin__semantic_locate, mcp__kin__find_references and mcp__kin__get_entity_source hand \
you, and read it with mcp__kin__get_entity_source first. mcp__kin__kin_mutate takes an \
operations array and stages and commits it in one call. Prefer verb 'patch' with target \
set to that UUID and an EntitySourcePatch payload: the exact source_base \
mcp__kin__get_entity_source returned, unchanged, and edits, each an old_text that occurs \
exactly once in the entity's body with the new_text that takes its place. The source_base \
names the version you read, so a change to an entity that has moved since is refused \
rather than applied over the newer text. When the change rewrites most of the entity, use \
verb 'update' with target set to its UUID, an EntitySourceBase payload holding that same \
exact source_base, and body set to its complete new source text. Every update must carry that \
EntitySourceBase, and one without it is refused: send the whole body back, not a fragment, \
because the body takes the entity's entire span. A body that came back marked '... [truncated]' is not the entity's source and \
staging one is refused. To add a top-level function, use verb 'create' with target set to \
an existing function's UUID and an EntityCreate payload: that function's source_base as the \
anchor, the new function's name, kind 'function', its one declaration as body, and \
placement 'sibling_after' or 'new_source_unit'. To delete one, use verb 'remove' with its \
UUID and an EntityRemove payload holding its source_base. Use only these operations, as the \
mcp__kin__kin_mutate schema describes them. Give every operation a description saying what \
it does, and pass a summary too: one sentence in your own words saying what the whole \
change does, which becomes the subject a human reads in history. Your session is already \
open: this run opened it once and sends it with every change, so do not start another. If \
mcp__kin__kin_mutate refuses, the reason comes back in the result: fix what it names and \
call it again.

Your tools are the ones on your belt and no others: this repository is a graph, and a change \
to it is a change to an entity. Every change goes through mcp__kin__kin_mutate, including a \
new entity if its operations offer one; there is no file creation. If the change needs \
something kin_mutate cannot make, stop and say so.

Work in small steps. Call one or two tools, read what came back, then decide. When you have \
the answer, say it in plain text without calling a tool.";

/// Where the code-changing paragraph of [`DEFAULT_SYSTEM_PROMPT`] starts and ends.
const CHANGE_PARAGRAPH_START: &str = "To change code, name the entity";
const CHANGE_PARAGRAPH_END: &str = "Work in small steps.";

/// The code-changing paragraph for a belt that carries no write tool at all.
const READ_ONLY_PARAGRAPH: &str = "\
This run carries no tool that changes code. Answer from what Kin tells you, and when the \
task needs a change, say exactly what the change is instead of making it.

Your tools are the mcp__kin__ ones named above. You have no others.

";

/// The built-in system prompt for this belt.
///
/// The paragraph about changing code has to describe the write tool the model
/// actually has, because a prompt that names a tool the belt does not carry is a
/// false instruction: under `--tool-profile agent-query` the server serves no
/// `kin_mutate`, and a model told to call it spends its turns being refused.
/// `kin_mutate` on the belt keeps the entity paragraph, and a belt without it is
/// told the run is read-only.
pub fn system_prompt_for(belt: &Belt) -> String {
    if belt.has_kin_tool("kin_mutate") {
        return DEFAULT_SYSTEM_PROMPT.to_string();
    }
    let (Some(start), Some(end)) = (
        DEFAULT_SYSTEM_PROMPT.find(CHANGE_PARAGRAPH_START),
        DEFAULT_SYSTEM_PROMPT.find(CHANGE_PARAGRAPH_END),
    ) else {
        return DEFAULT_SYSTEM_PROMPT.to_string();
    };
    format!(
        "{}{}{}",
        &DEFAULT_SYSTEM_PROMPT[..start],
        READ_ONLY_PARAGRAPH,
        &DEFAULT_SYSTEM_PROMPT[end..]
    )
}

/// One attached graph server and the repository it serves.
///
/// A run holds one of these per repository. Everything that has to reach a particular
/// graph goes through the server whose prefix the call names, which is what keeps a
/// two-repository run from committing one repository's change into the other's graph.
struct Server {
    /// `None` for a single-server run, whose tools keep the historical `mcp__kin__`
    /// prefix. `Some(label)` once several are attached and they must be told apart.
    label: Option<String>,
    repo: std::path::PathBuf,
    client: McpClient,
    declared: Vec<McpTool>,
    session: Option<String>,
    /// The session's idle window, as the reply that opened it named it in
    /// `idle_timeout_secs`. `None` when the reply named none, and then nothing is
    /// heartbeated on a guess.
    session_ttl: Option<Duration>,
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

/// What one tool cost a run, summed over every call to it.
#[derive(Debug, Clone, Default)]
struct ToolCost {
    calls: u32,
    error_calls: u32,
    /// Bytes the tool itself returned, before any cut.
    bytes_returned: u64,
    /// Bytes that reached the model, which is less when a result was cut or withheld.
    bytes_shown: u64,
    wall_ms: u128,
}

/// Which counting produced a run's token numbers.
///
/// Named in the record and never omitted. A byte heuristic at
/// [`crate::context::BYTES_PER_TOKEN`] and a model's own tokenizer disagree, often by
/// a lot, so two runs counted different ways are not comparable and a reader has to be
/// told which ruler each number came off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountingMode {
    /// Every completion carried the endpoint's own prompt and answer counts.
    EndpointUsage,
    /// Some completions carried a count and some did not, so the totals cover only
    /// part of the run. `requests_with_input_usage` and `requests_with_output_usage`
    /// say how much.
    EndpointUsagePartial,
    /// The endpoint counted nothing, and every dispatched request's prompt was counted
    /// by the server's own template and tokenizer. The answers were counted by nothing.
    LlamaCppTokenizer,
    /// The endpoint counted nothing, and at least one prompt count is the labeled byte
    /// heuristic rather than a tokenizer's. Not an upper bound for every tokenizer.
    Heuristic,
    /// Nothing counted anything: the run stopped before it dispatched a request.
    None,
}

impl AccountingMode {
    fn label(self) -> &'static str {
        match self {
            AccountingMode::EndpointUsage => "endpoint_usage",
            AccountingMode::EndpointUsagePartial => "endpoint_usage_partial",
            AccountingMode::LlamaCppTokenizer => "llama_cpp_tokenizer",
            AccountingMode::Heuristic => "heuristic",
            AccountingMode::None => "none",
        }
    }
}

struct Counters {
    tool_calls: u32,
    kin_calls: u32,
    refused_calls: u32,
    repairs: u32,
    unsafe_absence_events: u32,
    unreadable_results: u32,
    /// Results cut to the per-result ceiling before the model saw them.
    clipped_results: u32,
    /// Results the conversation could not hold, replaced by a note saying so.
    withheld_results: u32,
    /// Calls in a turn's batch that were never run because a budget was spent part way.
    skipped_calls: u32,
    /// Heartbeats sent to keep a Kin session alive through a long wait on the endpoint.
    session_heartbeats: u32,
    turns: u32,
    input_tokens: u64,
    output_tokens: u64,
    saw_usage: bool,
    /// Completions the endpoint returned, including one whose choice was rejected after
    /// the model had already generated it. Generation cost what it cost, so it is counted.
    completions: u32,
    /// How many of those carried the endpoint's own prompt count, and its own answer
    /// count, kept apart because an endpoint that reports one and not the other is
    /// ordinary and summing the missing half as zero reads as a measured zero.
    input_reports: u32,
    output_reports: u32,
    /// The admitted prompt count of every request this run dispatched, and how many of
    /// those counts came from the server's own tokenizer rather than the byte heuristic.
    /// Used only when the endpoint counted nothing, and never added to an endpoint count.
    admitted_prompt_tokens: u64,
    admitted_requests: u32,
    exact_admissions: u32,
    /// What each tool cost, keyed by the name the model called, so a refusal appears
    /// under the name the model invented rather than under nothing.
    by_tool: BTreeMap<String, ToolCost>,
    api_ms: u128,
    /// Entities the model named to `kin_mutate`, in the order it named them,
    /// published as `entities_changed`.
    ///
    /// An entity target is a UUID or a name and resolves against the graph, not
    /// the filesystem, which is the shape the thesis wants: the run records which
    /// entity changed, and the file it landed in is derived.
    entity_edits: Vec<String>,
    /// Every row `find_references` returned in this run, keyed by (focal
    /// entity id, referenced entity id) so a second call in the same run
    /// merges instead of colliding or duplicating.
    ///
    /// A T1 study task found Kin's `find_references` returning six rows for
    /// `toSSG`, every one `resolution: "type_resolved"`, and the model's own
    /// final ANSWER text dropping two of them (`bun/ssg.ts:2`,
    /// `deno/ssg.ts:1`, both attributed to a `Module`-kind entity) while
    /// keeping four others, including two more `Module`-kind rows from test
    /// files. Reading the transcript end to end found no code anywhere
    /// between the tool result and the model's turn that touches row content
    /// by kind or by anything else: `annotate` only ever appends an advisory
    /// note to Kin's own text, never removes from it, and the appended text
    /// goes to the model exactly as Kin returned the JSON. The drop was the
    /// model's own prose composition, not a belt filter. A belt that cannot
    /// make a model's free-text answer complete can still make completeness
    /// available without it: this field carries the full row set `to_json`
    /// reports, so a consumer who wants every reference Kin resolved,
    /// regardless of the referencing entity's kind, never has to depend on
    /// what the model chose to keep in its final text.
    reference_rows: BTreeMap<(String, String), Value>,
}

impl Counters {
    fn new() -> Self {
        Counters {
            tool_calls: 0,
            kin_calls: 0,
            refused_calls: 0,
            repairs: 0,
            unsafe_absence_events: 0,
            unreadable_results: 0,
            clipped_results: 0,
            withheld_results: 0,
            skipped_calls: 0,
            session_heartbeats: 0,
            turns: 0,
            input_tokens: 0,
            output_tokens: 0,
            saw_usage: false,
            completions: 0,
            input_reports: 0,
            output_reports: 0,
            admitted_prompt_tokens: 0,
            admitted_requests: 0,
            exact_admissions: 0,
            by_tool: BTreeMap::new(),
            api_ms: 0,
            entity_edits: Vec::new(),
            reference_rows: BTreeMap::new(),
        }
    }

    fn absorb(&mut self, usage: &Usage) {
        self.completions += 1;
        if let Some(value) = usage.input_tokens {
            self.input_tokens += value;
            self.input_reports += 1;
            self.saw_usage = true;
        }
        if let Some(value) = usage.output_tokens {
            self.output_tokens += value;
            self.output_reports += 1;
            self.saw_usage = true;
        }
    }

    /// Count one request the loop admitted and dispatched, with the prompt count that
    /// admitted it and whether that count came from a tokenizer or the byte heuristic.
    fn record_admission(&mut self, tokens: u64, exact: bool) {
        self.admitted_prompt_tokens = self.admitted_prompt_tokens.saturating_add(tokens);
        self.admitted_requests += 1;
        if exact {
            self.exact_admissions += 1;
        }
    }

    /// Count one tool call the run actually attempted.
    ///
    /// `produced` is what the tool itself returned and `shown` is what reached the
    /// model, and they differ exactly when a result was cut to the per-result ceiling
    /// or withheld for the context budget. A call that was never run because a budget
    /// was spent part way through a batch is not counted here; it is `skipped_calls`.
    fn record_call(
        &mut self,
        name: &str,
        wall_ms: u128,
        produced: usize,
        shown: usize,
        is_error: bool,
    ) {
        let cost = self.by_tool.entry(name.to_string()).or_default();
        cost.calls += 1;
        if is_error {
            cost.error_calls += 1;
        }
        cost.bytes_returned = cost.bytes_returned.saturating_add(produced as u64);
        cost.bytes_shown = cost.bytes_shown.saturating_add(shown as u64);
        cost.wall_ms = cost.wall_ms.saturating_add(wall_ms);
    }

    /// Read a `find_references` result's `references` array and fold every row
    /// into the run's own record of what Kin returned, keyed by (focal entity,
    /// referenced entity) so a second call in the same run merges rather than
    /// duplicating or overwriting a different question's rows.
    ///
    /// Best-effort and silent on anything that is not this exact shape: a
    /// result from a different tool, an error payload, or text that does not
    /// parse as the expected JSON adds nothing and never fails the call it
    /// came from. The row a consumer gets back is a fixed, minimal subset of
    /// what Kin returned, not the whole object, so this record does not grow
    /// a new implicit schema every time Kin adds a field to the real one.
    fn record_reference_rows(&mut self, tool: &str, raw_text: &str) {
        if tool != "find_references" {
            return;
        }
        let Ok(payload) = serde_json::from_str::<Value>(raw_text) else {
            return;
        };
        let Some(references) = payload.get("references").and_then(Value::as_array) else {
            return;
        };
        let focal_id = payload
            .get("focal_entity")
            .and_then(|focal| focal.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        for row in references {
            let Some(entity_id) = row.get("entity_id").and_then(Value::as_str) else {
                continue;
            };
            let record = json!({
                "focal_entity_id": focal_id,
                "entity_id": entity_id,
                "file_path": row.get("file_path").cloned().unwrap_or(Value::Null),
                "name": row.get("name").cloned().unwrap_or(Value::Null),
                "kind": row.get("kind").cloned().unwrap_or(Value::Null),
                "resolution": row.get("resolution").cloned().unwrap_or(Value::Null),
                "role": row.get("role").cloned().unwrap_or(Value::Null),
                "reference_lines": row.get("reference_lines").cloned().unwrap_or(Value::Null),
            });
            self.reference_rows
                .insert((focal_id.clone(), entity_id.to_string()), record);
        }
    }

    /// Which counting produced this run's token numbers.
    fn accounting_mode(&self) -> AccountingMode {
        if self.completions > 0
            && self.input_reports == self.completions
            && self.output_reports == self.completions
        {
            return AccountingMode::EndpointUsage;
        }
        if self.input_reports > 0 || self.output_reports > 0 {
            return AccountingMode::EndpointUsagePartial;
        }
        if self.admitted_requests == 0 {
            return AccountingMode::None;
        }
        if self.exact_admissions == self.admitted_requests {
            AccountingMode::LlamaCppTokenizer
        } else {
            AccountingMode::Heuristic
        }
    }

    /// What the run spent, summarized from the rows the transcript and the trace
    /// already carry, so a reader does not have to join two files to state a cost.
    ///
    /// `accounting_mode` is mandatory and never omitted, because a byte heuristic and a
    /// tokenizer count are two different rulers and a reader comparing a number from one
    /// against a number from the other, with nothing saying which is which, is comparing
    /// nothing. Endpoint counts are preferred whenever the endpoint reported any, and a
    /// heuristic count is never summed into a counted one.
    fn cost_json(&self, stop: &Stop) -> Value {
        let mode = self.accounting_mode();
        let (input, output) = match mode {
            AccountingMode::EndpointUsage | AccountingMode::EndpointUsagePartial => (
                (self.input_reports > 0).then_some(self.input_tokens),
                (self.output_reports > 0).then_some(self.output_tokens),
            ),
            // Nothing counted the answers, so the answer count stays absent rather than
            // becoming a zero that reads like a measurement.
            AccountingMode::LlamaCppTokenizer | AccountingMode::Heuristic => {
                (Some(self.admitted_prompt_tokens), None)
            }
            AccountingMode::None => (None, None),
        };
        let by_tool: Map<String, Value> = self
            .by_tool
            .iter()
            .map(|(name, cost)| {
                (
                    name.clone(),
                    json!({
                        "calls": cost.calls,
                        "error_calls": cost.error_calls,
                        "bytes_returned": cost.bytes_returned,
                        "bytes_shown": cost.bytes_shown,
                        "wall_ms": cost.wall_ms as u64,
                    }),
                )
            })
            .collect();
        json!({
            "accounting_mode": mode.label(),
            "total_input_tokens": input,
            "total_output_tokens": output,
            "requests": self.completions,
            "requests_with_input_usage": self.input_reports,
            "requests_with_output_usage": self.output_reports,
            "stop_reason": stop.reason,
            "tool_calls": self.tool_calls,
            "error_calls": self.by_tool.values().map(|cost| cost.error_calls).sum::<u32>(),
            "by_tool": Value::Object(by_tool),
        })
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
            "refused_calls": self.refused_calls,
            "repairs": self.repairs,
            "unsafe_absence_events": self.unsafe_absence_events,
            "unreadable_results": self.unreadable_results,
            "clipped_results": self.clipped_results,
            "withheld_results": self.withheld_results,
            "skipped_calls": self.skipped_calls,
            "session_heartbeats": self.session_heartbeats,
            "entities_changed": self.entity_edits,
            "reference_rows": self.reference_rows.values().cloned().collect::<Vec<_>>(),
        })
    }
}

/// The arguments a Kin call goes out with, with the harness's own session id
/// filled in where the tool needs one and the model could not have known it.
///
/// `kin_mutate` is the only model-facing tool that opens a transaction, and the
/// daemon resolves a transaction against a session it already holds.
/// `kin_session_start` is harness-owned (`belt::is_harness_owned`), so it never
/// reaches the model and the model cannot name the session the harness opened.
/// Without this, an unnamed session fell through to the MCP server's own
/// in-process registry, which in daemon mode is not the authority: it would
/// invent an id the daemon has never heard of and `kin_transaction_begin` would
/// refuse it, so the one write tool on a pure-Kin belt could never commit.
///
/// A session the model DID name is left exactly as it wrote it. Overriding one
/// would hide a caller's mistake behind a silent correction, and the refusal it
/// earns says more than a commit against a session it did not ask for.
pub(crate) fn with_harness_session(arguments: &Value, tool: &str, session: Option<&str>) -> Value {
    let (Some(session), "kin_mutate") = (session, tool) else {
        return arguments.clone();
    };
    let mut arguments = arguments.clone();
    let Some(map) = arguments.as_object_mut() else {
        return arguments;
    };
    let already_named = map
        .get("session_id")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());
    if !already_named {
        map.insert("session_id".into(), Value::String(session.to_string()));
    }
    arguments
}

/// The first line `kin_mutate` puts on a refusal that started nothing.
///
/// kin-mcp's `mutate_through` writes it only when the begin was refused because the
/// session it named no longer exists, and follows it with a JSON object naming the stage,
/// the refusal and that session. Mirrored rather than imported because kin-agent takes no
/// kin-mcp dependency.
const MUTATE_NOT_STARTED: &str = "kin_mutate_not_started: ";

/// Whether a refused Kin call is sent once more under a fresh session.
///
/// Only a `kin_mutate` whose first line is the not-started marker, for the begin stage,
/// refused because the session is gone, naming the session this run sent. A session the
/// model named itself is the model's to correct, and a call carrying a `request_id`
/// belongs to the durable protocol, which retries under its own identity.
///
/// The retry cannot apply a change twice, because the marker exists only where nothing
/// was started. An unkeyed `kin_mutate` is a begin followed by a commit that carries the
/// operations, and `kin_mcp::handlers::sessions::mutate_through` writes the marker only in
/// the branch where the begin itself was refused, before any commit is sent. A gone
/// session found later, by the commit or by the abort after an unanswered commit, can
/// arrive after a change was published, so its words may appear in the text, but never
/// on the first line as the marker, and this reads nothing else.
///
/// A Kin server hands its refusal over inside the envelope, which wraps text that is not
/// JSON as `{"_kin": …, "message": <text>}`, so the marker is the first line of `message`
/// there and the first line of the text only from a server that does not wrap.
pub(crate) fn retry_under_fresh_session(
    tool: &str,
    sent_by_model: &Value,
    outcome: &ToolOutcome,
    harness_session: Option<&str>,
) -> bool {
    let named = |key: &str| {
        sent_by_model
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    };
    if tool != "kin_mutate" || !outcome.is_error || named("session_id") || named("request_id") {
        return false;
    }
    let Some(harness_session) = harness_session else {
        return false;
    };
    let Some(marker) = refusal_text(&outcome.text)
        .lines()
        .next()
        .and_then(|line| line.strip_prefix(MUTATE_NOT_STARTED))
        .and_then(|marker| serde_json::from_str::<Value>(marker).ok())
    else {
        return false;
    };
    marker["stage"] == "begin"
        && marker["refusal"] == "session_not_found"
        && marker["session_id"] == harness_session
}

/// The refusal a Kin tool result carries: the envelope's `message` when the server
/// wrapped text that is not JSON in it, and the text itself otherwise.
fn refusal_text(text: &str) -> String {
    match serde_json::from_str::<Value>(text.trim()) {
        Ok(Value::Object(payload)) => match payload.get("message") {
            Some(Value::String(message)) => message.clone(),
            _ => text.to_string(),
        },
        _ => text.to_string(),
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
    /// The run kept asking a question that had stopped answering. Not a budget
    /// in the sense the other two are, and ended the same way on purpose: the
    /// model is asked for its answer with the tools taken away, so a run that
    /// was going in circles finishes by saying what it could not determine
    /// instead of by running out of window.
    Repeat,
}

/// Why a turn got no completion.
enum EndpointStop {
    /// The run's deadline passed before the endpoint answered.
    Deadline { waited: Duration },
    /// The endpoint failed in its own right.
    Failed(ProviderError),
}

/// Optional admission controls; existing AgentConfig callers remain compatible.
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    pub accounting: RequestAccounting,
    pub output_reserve_tokens: Option<u64>,
    /// Which belt this run puts on the model. `None` reads `KIN_AGENT_BELT`.
    ///
    /// Named here as well as in the environment because a caller that wants the
    /// wide belt for one run should not have to set a process-wide variable to
    /// get it, and a test that did would be setting it for every other test
    /// sharing the process.
    pub belt: Option<belt::BeltProfile>,
}
impl Default for RunOptions {
    fn default() -> Self {
        Self {
            accounting: RequestAccounting::Heuristic,
            output_reserve_tokens: None,
            belt: None,
        }
    }
}

fn parse_output_reserve(value: &str) -> anyhow::Result<u64> {
    let reserve = value.parse::<u64>().map_err(|_| {
        anyhow::anyhow!("KIN_AGENT_OUTPUT_RESERVE_TOKENS must be a positive integer")
    })?;
    anyhow::ensure!(
        reserve > 0,
        "KIN_AGENT_OUTPUT_RESERVE_TOKENS must be a positive integer"
    );
    Ok(reserve)
}

/// Run one task to completion.
pub fn run(config: AgentConfig) -> anyhow::Result<RunOutcome> {
    let accounting = match std::env::var("KIN_AGENT_CONTEXT_ACCOUNTING") {
        Err(std::env::VarError::NotPresent) => RequestAccounting::Heuristic,
        Ok(value) if value == "heuristic" => RequestAccounting::Heuristic,
        Ok(value) if value == "llama_cpp" => RequestAccounting::LlamaCpp,
        _ => anyhow::bail!("KIN_AGENT_CONTEXT_ACCOUNTING must be heuristic or llama_cpp"),
    };
    let output_reserve_tokens = match std::env::var("KIN_AGENT_OUTPUT_RESERVE_TOKENS") {
        Err(std::env::VarError::NotPresent) => None,
        Ok(value) => Some(parse_output_reserve(&value)?),
        Err(_) => anyhow::bail!("KIN_AGENT_OUTPUT_RESERVE_TOKENS must be a positive integer"),
    };
    run_with_options(
        config,
        RunOptions {
            accounting,
            output_reserve_tokens,
            belt: None,
        },
    )
}

/// Run with explicit request accounting without changing process-wide environment.
pub fn run_with_accounting(
    config: AgentConfig,
    accounting: RequestAccounting,
) -> anyhow::Result<RunOutcome> {
    run_with_options(
        config,
        RunOptions {
            accounting,
            ..RunOptions::default()
        },
    )
}

/// Run with a chosen counting contract and optional output reserve. Invalid overrides
/// fail before creating a transcript, attaching a graph server, or contacting the model.
pub fn run_with_options(config: AgentConfig, options: RunOptions) -> anyhow::Result<RunOutcome> {
    // `KIN_AGENT_PURE_KIN=false` used to put the local file tools on the belt.
    // They are retired, so the value is refused by name here, before any run I/O,
    // rather than ignored: a run that quietly dropped it would not be the run the
    // operator asked for, and nothing would say so.
    belt::refuse_file_tools(std::env::var("KIN_AGENT_PURE_KIN").ok().as_deref())
        .map_err(anyhow::Error::msg)?;
    if let Some(reserve) = options.output_reserve_tokens {
        anyhow::ensure!(
            reserve > 0 && reserve < config.context.tokens,
            "output reserve must be positive and below the {}-token context window (got {reserve})",
            config.context.tokens
        );
    }
    let accounting = options.accounting;
    let output_reserve = options
        .output_reserve_tokens
        .unwrap_or_else(|| config.context.answer_reserve());
    let started = Instant::now();
    // Validate the provider dialect before transcript or MCP I/O. Construction sends no request.
    let provider = Provider::new(config.provider.clone())?;
    let session_id = uuid::Uuid::new_v4().to_string();
    let mut writer = TranscriptWriter::create(&config.out_dir, &session_id)?;
    let mut counters = Counters::new();

    // Every wait in the run, the endpoint's included, is measured against this one instant.
    let deadline_at = started + config.deadline;
    let result_ceiling = config.result_ceiling();

    // Resolved once, before the run record is written, so the provenance line,
    // the filter below and the specs sent to the endpoint cannot disagree about
    // which belt this run had.
    let belt_profile = options.belt.unwrap_or_else(belt::BeltProfile::from_env);
    let agent_meta = json!({
        "base_url": config.provider.base_url,
        "max_tool_calls": config.max_tool_calls,
        "deadline_s": config.deadline.as_secs(),
        "context_tokens": config.context.tokens,
        "output_reserve_tokens": output_reserve,
        "output_token_parameter": provider.output_token_parameter(),
        "context_source": config.context.source.label(),
        "context_accounting": match accounting { RequestAccounting::Heuristic => "heuristic", RequestAccounting::LlamaCpp => "llama_cpp" },
        "max_result_bytes": result_ceiling,
        "tool_profile": config.tool_profile.clone().unwrap_or_else(|| "server-default".into()),
        // Which belt this run had, recorded beside the server profile because
        // they are different settings. The belt is Kin tools only, so a change
        // in this run went through Kin or it did not happen; the field stays so
        // a run reads the same way as the ones recorded before the file tools
        // were retired.
        "belt": "pure-kin",
        "belt_profile": belt_profile.as_str(),
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
            session_ttl: None,
        });
    }

    let mut kin_tools: Vec<belt::KinTool> = Vec::new();
    for (index, server) in servers.iter().enumerate() {
        let prefix = belt::tool_prefix(server.label.as_deref());
        for tool in &server.declared {
            if belt::is_harness_owned(&tool.name) {
                continue;
            }
            if belt_profile == belt::BeltProfile::Default && belt::is_opt_in(&tool.name) {
                continue;
            }
            kin_tools.push(belt::KinTool {
                folded: false,
                server: index,
                bare: tool.name.clone(),
                exposed: format!("{prefix}{}", tool.name),
                description: tool.description.clone(),
                schema: tool.input_schema.clone(),
            });
        }
    }
    belt::fold_traversal(&mut kin_tools);
    let belt = Belt::new(kin_tools);
    let specs = belt.to_specs();
    let tool_names: Vec<String> = belt.names().iter().cloned().collect();

    writer.init(
        &config.provider.model,
        &config.repo,
        &tool_names,
        "connected",
        &[],
        agent_meta,
    )?;

    // Open a Kin session per server, so every mutation this run makes names this agent.
    // A server without the tool is not an error; it just means the session is unavailable
    // there and the trace says so.
    for server in servers.iter_mut() {
        let session = start_kin_session(server, &config, &mut writer)?;
        server.session = session;
    }

    let mut system_prompt = config
        .system_prompt
        .clone()
        .unwrap_or_else(|| system_prompt_for(&belt));
    // The repository roots are a fact about this run that the model cannot infer, and
    // without them it cannot address the second repository at all, so the note is appended
    // to an operator-supplied prompt as well as to the built-in one.
    if multi {
        let roots = servers
            .iter()
            .map(|server| server.repo.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        system_prompt.push_str(&format!(
            "\n\nThe repositories attached to this run are: {roots}. Each has its own Kin \
             graph, and its tools carry that repository's own prefix, so read the tool names \
             you were given and call the one belonging to the repository you mean."
        ));
    }
    // The first request carries the system prompt, the task and every tool spec, and the
    // meter reads their size until the endpoint reports a count of its own.
    let baseline_bytes = system_prompt.len()
        + config.task.len()
        + serde_json::to_vec(&specs).map_or(0, |bytes| bytes.len());
    let mut meter =
        ContextMeter::with_reserve(config.context, baseline_bytes as u64, output_reserve);
    let mut messages = vec![
        json!({ "role": "system", "content": system_prompt }),
        json!({ "role": "user", "content": config.task }),
    ];

    let mut next_tool_id = 0u64;
    let mut consecutive_unusable = 0u32;
    let mut repeat_guard = repeat::RepeatGuard::new();
    // Set when the guard decided the run should answer rather than ask again.
    let mut repeat_stop: Option<String> = None;
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
        let mut prepared = None;
        let spent = if counters.tool_calls >= config.max_tool_calls {
            Some(Spent::ToolCalls)
        } else if context_note.is_some() {
            Some(Spent::Context)
        } else if repeat_stop.is_some() {
            Some(Spent::Repeat)
        } else {
            match prepare_turn(
                &provider,
                &messages,
                &specs,
                accounting,
                &mut meter,
                deadline_at,
                &mut counters,
                &mut writer,
                false,
            )? {
                Ok(Some(request)) => {
                    prepared = Some(request);
                    None
                }
                Ok(None) => Some(Spent::Context),
                Err(error) => {
                    (stop, final_text) = accounting_stop(&config, error);
                    break;
                }
            }
        };
        if let Some(spent) = spent {
            // A budget is spent. Ask for an answer with nothing to call, so the run ends
            // with what the model actually learned rather than with silence.
            let (spent_stop, prompt) = budget_stop(
                spent,
                &config,
                &meter,
                context_note.as_deref(),
                repeat_stop.as_deref(),
                counters.turns,
            );
            stop = spent_stop;
            if matches!(spent, Spent::Context) && counters.turns == 0 {
                // The first request alone does not fit, so nothing was learned to ask for.
                break;
            }
            messages.push(json!({ "role": "user", "content": prompt }));
            let request = match prepare_turn(
                &provider,
                &messages,
                &[],
                accounting,
                &mut meter,
                deadline_at,
                &mut counters,
                &mut writer,
                true,
            )? {
                Ok(Some(request)) => request,
                Ok(None) => {
                    final_text =
                        "(no final answer: the complete request leaves no admitted output room)"
                            .into();
                    break;
                }
                Err(error) => {
                    (stop, final_text) = accounting_stop(&config, error);
                    break;
                }
            };
            match wait_for_turn(
                &provider,
                &request,
                &mut counters,
                deadline_at,
                &mut servers,
                &mut writer,
            )? {
                Ok(completion) => {
                    record_completion(&mut counters, &mut writer, &completion)?;
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
                    if err.is_accounting_failure() {
                        record_accounting_failure(&mut meter, &mut counters, &mut writer, &err)?;
                        (stop, final_text) = accounting_stop(&config, EndpointStop::Failed(err));
                    } else {
                        final_text = format!("(no final answer: {err})");
                    }
                }
            }
            break;
        }

        let completion = match wait_for_turn(
            &provider,
            &prepared.expect("ordinary turn was admitted"),
            &mut counters,
            deadline_at,
            &mut servers,
            &mut writer,
        )? {
            Ok(completion) => completion,
            Err(EndpointStop::Deadline { waited }) => {
                stop = Stop::deadline(
                    &config,
                    &format!("while waiting {} s on the endpoint", waited.as_secs()),
                );
                break;
            }
            Err(EndpointStop::Failed(err)) => {
                if err.is_accounting_failure() {
                    record_accounting_failure(&mut meter, &mut counters, &mut writer, &err)?;
                    (stop, final_text) = accounting_stop(&config, EndpointStop::Failed(err));
                } else {
                    stop = Stop::new(
                        ExitStatus::EndpointError,
                        "endpoint_unreachable",
                        Some(err.to_string()),
                    );
                    final_text = err.to_string();
                }
                break;
            }
        };
        record_completion(&mut counters, &mut writer, &completion)?;
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
                    } else if repeat_stop.is_some() {
                        Some(
                            "this run stopped re-asking a question the graph had already answered"
                                .to_string(),
                        )
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
                            "args": call.arguments,
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
                    // One clock over every call, whatever it routes to, so a refusal and a
                    // graph call are timed the same way and the per-tool wall time can be
                    // added up without knowing which surface answered.
                    let call_started = Instant::now();
                    // Set only where the tool's own answer is bigger than what the model is
                    // sent, which is the Kin result that was cut to the per-result ceiling.
                    let mut produced_bytes: Option<usize> = None;
                    // Routed with the arguments, not just the name: a folded
                    // belt tool picks its server tool from what the model sent,
                    // and the arguments that go out are the ones the route
                    // resolved with.
                    let routed = belt.route_call(&call.name, &call.arguments);
                    let routed_arguments = routed.arguments;
                    let route = routed.route;
                    // The guard sees a Kin call before it is sent. A call it
                    // stops still cost the model a turn, so it stays counted
                    // above, and it still gets an answer so the conversation
                    // stays well formed.
                    let guarded = match &route {
                        Route::Kin { tool, .. } => repeat_guard.before(tool, &routed_arguments),
                        Route::Refused(_) => repeat::Verdict::Allow,
                    };
                    if guarded != repeat::Verdict::Allow {
                        let (text, ends_run) = match guarded {
                            repeat::Verdict::Redirect(message) => (message, None),
                            repeat::Verdict::Exhausted(detail) => (
                                format!(
                                    "[kin agent] This call was not run: {detail}. Answer now with \
                                     what you have learned, and name what you could not determine \
                                     and which tool could not answer it."
                                ),
                                Some(detail),
                            ),
                            repeat::Verdict::Allow => unreachable!("checked above"),
                        };
                        writer.trace(json!({
                            "tool_use_id": call.id,
                            "surface": "policy",
                            "tool": call.name,
                            "args": call.arguments,
                            "policy": "repeat_guard",
                            "verdict": if ends_run.is_some() { "exhausted" } else { "redirected" },
                            "reason": repeat_guard.reasons().last(),
                            "escalations": repeat_guard.escalations(),
                            "is_error": true,
                        }))?;
                        // The guard's refusal is this call's result: it went back to the model
                        // marked as an error, so it takes a per-tool row like every other answered
                        // call. `tool_calls` was incremented above on purpose, and the cost summary
                        // asserts the per-tool rows add up to it, so a guarded call that skipped
                        // `record_call` would leave the headline counting a call no row accounts
                        // for. Nothing was cut, so what the tool produced and what the model was
                        // shown are the same bytes.
                        counters.record_call(
                            &call.name,
                            call_started.elapsed().as_millis(),
                            text.len(),
                            text.len(),
                            true,
                        );
                        writer.tool_result(&call.id, &text, true)?;
                        meter.add(text.len() as u64);
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": text,
                        }));
                        if let Some(detail) = ends_run {
                            repeat_stop = Some(detail);
                        }
                        continue;
                    }
                    // A refusal is small and the model must hear it; only a Kin answer is
                    // ever withheld for size.
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
                                    let session = servers[server_index].session.clone();
                                    let mut arguments = with_harness_session(
                                        &routed_arguments,
                                        &name,
                                        session.as_deref(),
                                    );
                                    let mut outcome =
                                        servers[server_index].client.call_tool(&name, &arguments);
                                    // A daemon that restarted mid-run no longer holds the
                                    // session this run opened. When the begin is refused
                                    // for that, nothing was started, and the refusal says
                                    // so on its first line; the run opens a new session and
                                    // sends the same call once more under it.
                                    let gone = match &outcome {
                                        Ok(refused)
                                            if retry_under_fresh_session(
                                                &name,
                                                &routed_arguments,
                                                refused,
                                                session.as_deref(),
                                            ) =>
                                        {
                                            Some((
                                                refused.wall_ms,
                                                refusal_text(&refused.text)
                                                    .chars()
                                                    .take(300)
                                                    .collect::<String>(),
                                            ))
                                        }
                                        _ => None,
                                    };
                                    if let Some((wall_ms, detail)) = gone {
                                        writer.trace(json!({
                                            "tool_use_id": call.id,
                                            "surface": "kin",
                                            "server": server_name,
                                            "tool": name,
                                            "args": arguments,
                                            "wall_ms": wall_ms as u64,
                                            "is_error": true,
                                            "policy": "allowed",
                                            "event": "session_gone",
                                            "detail": detail,
                                        }))?;
                                        if let Some(fresh) = start_kin_session(
                                            &mut servers[server_index],
                                            &config,
                                            &mut writer,
                                        )? {
                                            servers[server_index].session = Some(fresh.clone());
                                            arguments = with_harness_session(
                                                &routed_arguments,
                                                &name,
                                                Some(&fresh),
                                            );
                                            outcome = servers[server_index]
                                                .client
                                                .call_tool(&name, &arguments);
                                        }
                                    }
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
                                            // Recorded on the way out, because this exit
                                            // skips the loop's own accounting below and a
                                            // call the run made must not be missing from
                                            // the summary it reports.
                                            counters.record_call(
                                                &call.name,
                                                call_started.elapsed().as_millis(),
                                                err.to_string().len(),
                                                err.to_string().len(),
                                                true,
                                            );
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
                                            produced_bytes = Some(result_bytes);
                                            let mut shown_bytes = result_bytes;
                                            // Read off the FULL text, before any clip below
                                            // shortens what the model is shown: the run's own
                                            // record of what Kin returned must not depend on
                                            // how much of it fit in the model's window.
                                            if !outcome.is_error {
                                                counters
                                                    .record_reference_rows(&name, &outcome.text);
                                            }
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
                                            // Read before the envelope notes go
                                            // on, so the guard grades what Kin
                                            // returned rather than what the
                                            // harness added about it.
                                            repeat_guard.record(
                                                &name,
                                                &arguments,
                                                &outcome.text,
                                                outcome.is_error,
                                            );
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
                                                // What went out, not what the
                                                // model wrote, because the two
                                                // differ once the harness fills
                                                // in a session the model cannot
                                                // see, and a trace that shows
                                                // the second explains neither a
                                                // refusal nor a commit.
                                                "args": arguments,
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
                                            // What the run changed, read off
                                            // the call the model made. The
                                            // graph is the record of the change
                                            // itself; this is the run's own
                                            // account of what it asked for.
                                            // Only a call that came back clean
                                            // counts: a refused mutate changed
                                            // nothing, and a run that listed its
                                            // refusals as edits would overstate
                                            // itself in exactly the place a
                                            // reader checks.
                                            if name == "kin_mutate" && !outcome.is_error {
                                                if let Some(ops) = call
                                                    .arguments
                                                    .get("operations")
                                                    .and_then(Value::as_array)
                                                {
                                                    for op in ops {
                                                        let Some(target) = op
                                                            .get("target")
                                                            .and_then(Value::as_str)
                                                            .map(str::trim)
                                                            .filter(|target| !target.is_empty())
                                                        else {
                                                            continue;
                                                        };
                                                        if !counters
                                                            .entity_edits
                                                            .iter()
                                                            .any(|seen| seen == target)
                                                        {
                                                            counters
                                                                .entity_edits
                                                                .push(target.to_string());
                                                        }
                                                    }
                                                }
                                            }
                                            (annotated, outcome.is_error)
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
                    counters.record_call(
                        &call.name,
                        call_started.elapsed().as_millis(),
                        produced_bytes.unwrap_or(result_text.len()),
                        result_text.len(),
                        is_error,
                    );
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
    repeated: Option<&str>,
    turns: u32,
) -> (Stop, String) {
    const ASK: &str = "Do not call any more tools. Answer now in plain text with what you have \
                       learned, and say plainly what you were not able to determine.";
    match spent {
        // Named apart from the tool-call cap it shares an exit code with. Both
        // are a run that ran out of room to ask, and only this one says the room
        // went on the same question twice, which is the difference a reader
        // grading a run needs and an exit code cannot carry.
        Spent::Repeat => (
            Stop::new(
                ExitStatus::CapReached,
                "repeat_loop",
                Some(
                    repeated
                        .unwrap_or("the run kept asking a question that had stopped answering")
                        .to_string(),
                ),
            ),
            format!(
                "You were asking the same question repeatedly and it had stopped producing \
                 anything new. {ASK}"
            ),
        ),
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
            // The stop names what counted as well as how much. A stop read
            // against a number whose source is unstated cannot be checked, and
            // the byte heuristic and the endpoint's own count disagree by
            // enough to end a run that had room left.
            let counted = meter.count_source().label();
            let detail = match withheld {
                Some(withheld) => withheld.to_string(),
                None if turns == 0 => format!(
                    "the first request needs about {} tokens, {counted}, which leaves less than \
                     the {} kept for the answer in the model's {}-token window ({})",
                    meter.used(),
                    meter.reserve(),
                    window.tokens,
                    window.source.label()
                ),
                None => format!(
                    "the conversation holds about {} of the model's {} tokens ({} window, \
                     {counted}), which leaves less than the {} kept for the answer",
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

fn check_arguments(belt: &Belt, name: &str, arguments: &Value) -> Result<(), String> {
    if let Some(problem) = parse::arguments_are_malformed(arguments) {
        return Err(problem);
    }
    match belt.schema_for(name) {
        Some(schema) => belt::validate_arguments(&schema, arguments),
        None => Ok(()),
    }
}

/// Take one completion's cost, and write the endpoint's own count for that one request
/// to the trace beside it.
///
/// The per-request row is what makes the summary checkable: a reader can add the rows up
/// and get the totals back, and a request the endpoint counted nothing for says so with
/// nulls rather than dropping out of the file.
fn record_completion(
    counters: &mut Counters,
    writer: &mut TranscriptWriter,
    completion: &Completion,
) -> std::io::Result<()> {
    counters.absorb(&completion.usage);
    writer.trace(json!({
        "event": "request_usage",
        "request": counters.completions,
        "input_tokens": completion.usage.input_tokens,
        "output_tokens": completion.usage.output_tokens,
        "reported_by_endpoint": !completion.usage.is_empty(),
        "api_ms": completion.api_ms as u64,
    }))
}

fn record_accounting_failure(
    meter: &mut ContextMeter,
    counters: &mut Counters,
    writer: &mut TranscriptWriter,
    error: &ProviderError,
) -> anyhow::Result<()> {
    let reason = error.to_string();
    let observed_usage = if let ProviderError::RejectedCompletion { usage, .. } = error {
        // Rejection prevents dispatch of the choice, but cannot undo generation.
        counters.absorb(usage);
        usage.to_json()
    } else {
        None
    };
    meter.accounting_failed(&reason);
    writer.trace(json!({"event":"context_accounting_failed", "reason":reason, "exact":false, "admitted":false,
        "completion_rejected":matches!(error, ProviderError::RejectedCompletion { .. }), "observed_usage":observed_usage}))?;
    Ok(())
}

fn accounting_stop(config: &AgentConfig, error: EndpointStop) -> (Stop, String) {
    match error {
        EndpointStop::Deadline { .. } => (
            Stop::deadline(config, "while counting the complete request"),
            String::new(),
        ),
        EndpointStop::Failed(error) => (
            Stop::new(
                ExitStatus::EndpointError,
                "context_accounting_failed",
                Some(error.to_string()),
            ),
            error.to_string(),
        ),
    }
}

/// Count and admit the full body, including the tool-free closing request. A shorter final
/// answer changes the output bound, so that exact body must be counted again before dispatch.
#[allow(clippy::too_many_arguments)]
fn prepare_turn(
    provider: &Provider,
    messages: &[Value],
    tools: &[Value],
    accounting: RequestAccounting,
    meter: &mut ContextMeter,
    deadline_at: Instant,
    counters: &mut Counters,
    writer: &mut TranscriptWriter,
    final_answer: bool,
) -> anyhow::Result<Result<Option<ChatRequest>, EndpointStop>> {
    let began = Instant::now();
    let mut request = provider.prepare_request(messages, tools, meter.reserve());
    let heuristic_floor = meter.used();
    for round in 0..3 {
        let remaining = deadline_at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            meter.accounting_failed("run deadline exhausted during counting");
            return Ok(Err(EndpointStop::Deadline {
                waited: began.elapsed(),
            }));
        }
        let asked = Instant::now();
        let measured = match accounting {
            RequestAccounting::Heuristic => Ok(PromptCount::Unsupported(
                "generic provider: byte heuristic selected".into(),
            )),
            RequestAccounting::LlamaCpp => provider.count_prompt_within(
                &request,
                remaining
                    .min(provider.config().request_timeout)
                    .min(Duration::from_secs(5)),
            ),
        };
        counters.api_ms += asked.elapsed().as_millis();
        let measured = match measured {
            Ok(value) if Instant::now() < deadline_at => value,
            result => {
                let reason = result.err().map_or_else(
                    || "run deadline exhausted during counting".into(),
                    |error| error.to_string(),
                );
                meter.accounting_failed(&reason);
                writer.trace(json!({"event":"context_accounting_failed", "reason":reason, "exact":false, "admitted":false}))?;
                return Ok(Err(if Instant::now() >= deadline_at {
                    EndpointStop::Deadline {
                        waited: began.elapsed(),
                    }
                } else {
                    EndpointStop::Failed(ProviderError::Accounting(reason))
                }));
            }
        };
        let (tokens, source, reason) = match measured {
            PromptCount::Counted(tokens) => (tokens, CountSource::Tokenizer, None),
            // Once the endpoint has counted this conversation itself, the byte
            // heuristic does not get to overrule it. `heuristic_floor` is the
            // endpoint's own count of the last request plus an estimate of only
            // what the loop appended since, so the history is counted and just
            // the delta is estimated. Taking the larger of that and a heuristic
            // over the whole body is what ended runs early: on qwen3-coder-next
            // the whole-body heuristic read 59,029 tokens for a request the
            // server counted at 46,523, and the run stopped for its context
            // budget with about 19,000 tokens free and the model mid-task.
            PromptCount::Unsupported(reason) if meter.anchored_on_endpoint() => {
                (heuristic_floor, CountSource::EndpointUsage, Some(reason))
            }
            PromptCount::Unsupported(reason) => (
                request.heuristic_tokens().max(heuristic_floor),
                CountSource::Heuristic,
                Some(reason),
            ),
        };
        let exact = source.exact();
        let room = meter.window().tokens.saturating_sub(tokens);
        let admitted = request.max_tokens() > 0 && request.max_tokens() <= room;
        let detail = json!({
            "event":"context_admission", "method":source.method(),
            "exact":exact, "contract":if exact {Some("rendered_text_add_special_false_parse_special_true")} else {None},
            "fallback_reason":reason, "prompt_tokens":tokens, "max_tokens":request.max_tokens(),
            "output_token_parameter":request.output_token_parameter(),
            "window_tokens":meter.window().tokens, "tool_free":tools.is_empty(), "round":round, "admitted":admitted,
        });
        meter.record_request(tokens, source, detail.clone());
        writer.trace(detail)?;
        if admitted {
            // Only the admitted round is dispatched, so only its count is the run's
            // cost. An earlier round's count was a request that never went out.
            counters.record_admission(tokens, exact);
            if exact {
                request.expect_prompt_tokens(tokens);
            }
            return Ok(Ok(Some(request)));
        }
        if !final_answer || room == 0 {
            return Ok(Ok(None));
        }
        request.set_max_tokens(room.min(meter.reserve()));
    }
    let reason = "rendered final request did not stabilize within its output budget";
    meter.accounting_failed(reason);
    writer.trace(json!({"event":"context_accounting_failed", "reason":reason, "exact":false, "admitted":false}))?;
    Ok(Err(EndpointStop::Failed(ProviderError::Accounting(
        reason.into(),
    ))))
}

/// Ask the endpoint for one turn, inside what is left of the run's deadline.
///
/// Every attempt carries the remaining budget as its timeout, and a retry never starts once
/// the budget is gone, so a slow endpoint ends the wait at the deadline rather than
/// stretching the run by a full request timeout per attempt. A failure that lands after the
/// deadline is the deadline's, whatever the transport said.
fn complete_with_retry(
    provider: &Provider,
    request: &ChatRequest,
    counters: &mut Counters,
    deadline_at: Instant,
    keepalive: &mut Keepalive<'_>,
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
        let outcome = keepalive.wait(provider, request, limit);
        // Time spent waiting is endpoint time whether or not an answer came back.
        counters.api_ms += asked.elapsed().as_millis();
        match outcome {
            Ok(completion) => return Ok(completion),
            // A parsed response has observed usage even if the deadline elapsed while
            // receiving it. Preserve the rejection so the caller records that cost once.
            Err(err @ ProviderError::RejectedCompletion { .. }) => {
                return Err(EndpointStop::Failed(err));
            }
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

/// One turn's wait on the endpoint, with every attached Kin session kept alive through it
/// and each heartbeat it sent written to the trace once the wait is over.
fn wait_for_turn(
    provider: &Provider,
    request: &ChatRequest,
    counters: &mut Counters,
    deadline_at: Instant,
    servers: &mut [Server],
    writer: &mut TranscriptWriter,
) -> anyhow::Result<Result<Completion, EndpointStop>> {
    let mut keepalive = Keepalive::new(servers);
    let outcome = complete_with_retry(provider, request, counters, deadline_at, &mut keepalive);
    counters.session_heartbeats += keepalive.beats;
    for row in keepalive.rows {
        writer.trace(row)?;
    }
    Ok(outcome)
}

/// Keeps every attached Kin session alive while the loop waits on the endpoint.
///
/// A session is reaped once it sits idle for the window the reply that opened it named, and
/// every Kin call refreshes it, so the one long idle stretch in a run is a model turn. A
/// turn can outlast the window: a deadline past it leaves room for three request timeouts on
/// one turn, and a long prompt's prefill runs for minutes. So while a request is in flight
/// each session is heartbeated at a third of its own window, and the heartbeats stop when
/// the turn returns. A session whose reply named no window is not heartbeated, because its
/// cadence would be a guess.
struct Keepalive<'a> {
    servers: &'a mut [Server],
    /// When each server's session was last refreshed during this wait, by server index.
    refreshed: Vec<Instant>,
    /// A trace row per heartbeat, written by the caller once the wait returns.
    rows: Vec<Value>,
    beats: u32,
}

impl<'a> Keepalive<'a> {
    fn new(servers: &'a mut [Server]) -> Self {
        let refreshed = vec![Instant::now(); servers.len()];
        Keepalive {
            servers,
            refreshed,
            rows: Vec::new(),
            beats: 0,
        }
    }

    /// How often a server's session is heartbeated: a third of its window, and only for a
    /// session that is open and named one.
    fn cadence(server: &Server) -> Option<Duration> {
        server.session.as_ref()?;
        server.session_ttl.map(|ttl| ttl / 3)
    }

    /// The next instant any session is due a heartbeat.
    fn next_due(&self) -> Option<Instant> {
        self.servers
            .iter()
            .zip(&self.refreshed)
            .filter_map(|(server, refreshed)| Self::cadence(server).map(|every| *refreshed + every))
            .min()
    }

    /// Heartbeat every session that is due one.
    fn beat_due(&mut self) {
        let now = Instant::now();
        for (index, server) in self.servers.iter_mut().enumerate() {
            let Some(every) = Self::cadence(server) else {
                continue;
            };
            if now < self.refreshed[index] + every {
                continue;
            }
            let session = server.session.clone().unwrap_or_default();
            let outcome = server
                .client
                .call_tool("kin_session_heartbeat", &json!({ "session_id": session }));
            self.refreshed[index] = Instant::now();
            self.beats += 1;
            self.rows.push(json!({
                "surface": "kin",
                "server": server.name(),
                "tool": "kin_session_heartbeat",
                "policy": "allowed",
                "event": "session_heartbeat",
                "kin_session_id": session,
                "wall_ms": outcome.as_ref().ok().map(|done| done.wall_ms as u64),
                "is_error": outcome.as_ref().map(|done| done.is_error).unwrap_or(true),
                "transport_error": outcome.as_ref().err().map(|err| err.to_string()),
                "ts": now_iso(),
            }));
        }
    }

    /// One endpoint attempt. With a session to keep, the request runs on its own thread and
    /// this one sends each heartbeat as it falls due, until the answer arrives.
    fn wait(
        &mut self,
        provider: &Provider,
        request: &ChatRequest,
        limit: Duration,
    ) -> Result<Completion, ProviderError> {
        if self.next_due().is_none() {
            return provider.complete_request_within(request, limit);
        }
        std::thread::scope(|scope| {
            let (answer, answered) = std::sync::mpsc::channel();
            let request_thread = scope.spawn(move || {
                // The receiver lives until this scope ends, so the send cannot fail.
                let _ = answer.send(provider.complete_request_within(request, limit));
            });
            loop {
                let until = self
                    .next_due()
                    .map_or(limit, |due| due.saturating_duration_since(Instant::now()));
                match answered.recv_timeout(until) {
                    Ok(outcome) => return outcome,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => self.beat_due(),
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        // The request thread ends without answering only when it panics, and
                        // the panic is carried here, as it would surface without the split.
                        match request_thread.join() {
                            Err(panic) => std::panic::resume_unwind(panic),
                            Ok(()) => unreachable!("the request thread always sends its answer"),
                        }
                    }
                }
            }
        })
    }
}

/// The idle window a session reply names in `idle_timeout_secs`, at its top level or one
/// level down. `None` when it names none, or zero: an in-process session reports no window,
/// and a heartbeat cadence is never guessed.
pub(crate) fn session_idle_timeout(outcome: &ToolOutcome) -> Option<Duration> {
    let payload: Value = serde_json::from_str(outcome.text.trim()).ok()?;
    let object = payload.as_object()?;
    let named =
        |object: &Map<String, Value>| object.get("idle_timeout_secs").and_then(Value::as_u64);
    let secs = named(object).or_else(|| {
        ["session", "result"].iter().find_map(|nested| {
            object
                .get(*nested)
                .and_then(Value::as_object)
                .and_then(named)
        })
    })?;
    (secs > 0).then_some(Duration::from_secs(secs))
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
            "detail": "the server does not expose kin_session_start, so a change this run makes carries no agent session",
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
            server.session_ttl = if outcome.is_error {
                None
            } else {
                session_idle_timeout(&outcome)
            };
            writer.trace(json!({
                "surface": "kin",
                "server": server_name,
                "tool": "kin_session_start",
                "policy": "allowed",
                "event": "session_start",
                "wall_ms": outcome.wall_ms as u64,
                "is_error": outcome.is_error,
                "kin_session_id": session.clone(),
                "idle_timeout_secs": server.session_ttl.map(|ttl| ttl.as_secs()),
            }))?;
            Ok(if outcome.is_error { None } else { session })
        }
        Err(err) => {
            server.session_ttl = None;
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

/// Resolution tiers meaning Kin bound this row to a real entity rather than
/// a same-name guess. Both are a real reference: an import line is exactly
/// that, not a lesser hit, so `import_scoped` counts on the same footing as
/// `type_resolved`. An unresolved `name_only` guess is not in this set.
fn is_resolved_reference(resolution: Option<&str>) -> bool {
    matches!(resolution, Some("type_resolved") | Some("import_scoped"))
}

/// Every `path:line` this run's `find_references` calls actually resolved,
/// across every recorded row and every line in a row's `reference_lines`,
/// deduplicated and in a stable order.
///
/// A study task found the belt keeping four of the six rows Kin resolved for
/// a symbol and dropping exactly the two aliased-import lines, both
/// attributed to a `Module`-kind entity, while an unrelated pair of
/// `Module`-kind test-file rows survived. Nothing here reads `kind` or
/// `role`: a resolved row counts on the same footing regardless of the
/// referencing entity's kind, so an import line stays with every other one.
fn resolved_reference_lines(reference_rows: &BTreeMap<(String, String), Value>) -> Vec<String> {
    let mut lines = BTreeSet::new();
    for row in reference_rows.values() {
        if !is_resolved_reference(row.get("resolution").and_then(Value::as_str)) {
            continue;
        }
        let Some(file_path) = row.get("file_path").and_then(Value::as_str) else {
            continue;
        };
        let Some(reference_lines) = row.get("reference_lines").and_then(Value::as_array) else {
            continue;
        };
        for line in reference_lines {
            if let Some(line) = line.as_u64() {
                lines.insert(format!("{file_path}:{line}"));
            }
        }
    }
    lines.into_iter().collect()
}

/// Whether `position` (a `path:line` string) is already in `text` as
/// itself, not merely as a prefix of a longer line number: `ssg.ts:2` must
/// not read as present because `ssg.ts:26` is in the text. A match counts
/// unless the character right after it is another ASCII digit.
fn contains_position(text: &str, position: &str) -> bool {
    text.match_indices(position)
        .any(|(start, _)| !text[start + position.len()..].starts_with(|c: char| c.is_ascii_digit()))
}

/// A line that is nothing but the literal word `ANSWER`, case-insensitive,
/// once whitespace, any wrapping backticks, and one trailing colon are
/// stripped. This is the shape both a fenced ANSWER block's opening line and
/// a standalone `ANSWER:` line take, so one check finds either.
fn is_answer_marker_line(line: &str) -> bool {
    let trimmed = line.trim().trim_matches('`').trim();
    let trimmed = trimmed.strip_suffix(':').unwrap_or(trimmed).trim();
    trimmed.eq_ignore_ascii_case("answer")
}

/// A bare fenced block's opening line: three backticks and nothing else.
/// Checked only once [`is_answer_marker_line`] has ruled out an ANSWER
/// fence. A fence carrying a language tag reads as a deliberate example
/// rather than an untitled answer, so it is left alone.
fn is_bare_fence_open_line(line: &str) -> bool {
    line.trim() == "```"
}

/// A line ending in a colon followed by one or more ASCII digits: the shape
/// every position a caller of this run keys on takes (`path:line`). Used
/// only to decide whether an answer with no marker is a position list that
/// should get one. A plain conversational or diagnostic line has no such
/// shape and is left alone.
fn looks_like_a_position_line(line: &str) -> bool {
    let line = line.trim().trim_matches('`');
    let Some(colon) = line.rfind(':') else {
        return false;
    };
    let (head, tail) = (&line[..colon], &line[colon + 1..]);
    !head.is_empty() && !tail.is_empty() && tail.bytes().all(|byte| byte.is_ascii_digit())
}

/// Guarantee this run's reported answer always carries a literal `ANSWER`
/// marker a caller can key off, and that every reference `find_references`
/// actually resolved in this run is named somewhere in it, even when the
/// model's own prose dropped one.
///
/// This applies two repairs together, found on the same study, because
/// either alone leaves a caller "recording the answer" empty-handed:
///
/// - A task where Kin's data was perfect and the model's own answer held
///   every gold row, but inside a bare fence with no `ANSWER` token anywhere
///   in the output, so a caller parsing for the marker got nothing even
///   though the list underneath it was exactly right.
/// - The task described on [`resolved_reference_lines`], where the marker
///   was present but two resolved rows were missing from it.
///
/// Neither repair removes anything the model wrote. An answer that already
/// carries the marker and already names every resolved row is returned
/// unchanged, and so is a plain answer with nothing missing, no marker, and
/// no line shaped like a position: an ordinary conversational reply is not
/// forced into a fence it never needed. This does not parse nested fences.
/// Relabelling stops at the first bare, tagless fence found, which is the
/// shape the evidenced case took.
fn compose_final_answer(
    model_text: &str,
    reference_rows: &BTreeMap<(String, String), Value>,
) -> String {
    let missing: Vec<String> = resolved_reference_lines(reference_rows)
        .into_iter()
        .filter(|position| !contains_position(model_text, position))
        .collect();
    let lines: Vec<&str> = model_text.lines().collect();
    let marker_at = lines.iter().copied().position(is_answer_marker_line);
    let trimmed_empty = model_text.trim().is_empty();

    if !trimmed_empty
        && missing.is_empty()
        && (marker_at.is_some() || !lines.iter().copied().any(looks_like_a_position_line))
    {
        return model_text.to_string();
    }

    // Extend an existing marker line in place, or relabel the first bare
    // fence if there is one, so injected rows land inside the same block a
    // caller's parser will read rather than after it.
    let insert_at = marker_at.or_else(|| lines.iter().copied().position(is_bare_fence_open_line));

    if let Some(index) = insert_at {
        let mut composed = String::new();
        for (i, line) in lines.iter().enumerate() {
            if i == index && marker_at.is_none() {
                composed.push_str("```ANSWER");
            } else {
                composed.push_str(line);
            }
            composed.push('\n');
            if i == index {
                for extra in &missing {
                    composed.push_str(extra);
                    composed.push('\n');
                }
            }
        }
        return composed;
    }

    let mut body = model_text.trim().to_string();
    if body.is_empty() {
        body = "(empty: this run produced no final answer text)".to_string();
    }
    for extra in &missing {
        body.push('\n');
        body.push_str(extra);
    }
    format!("```ANSWER\n{body}\n```")
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
    let status = stop.status;
    let mut agent = counters.to_json(status.code(), &stop);
    agent["max_result_bytes"] = json!(config.result_ceiling());
    // What the run spent, in one object, so a cost claim about a run is read off the
    // record rather than assembled by hand from two files, or estimated.
    agent["cost"] = counters.cost_json(&stop);
    // The budget as it stood when the run stopped, so a context stop can be read against
    // the numbers that decided it.
    agent["context"] = meter.map_or(Value::Null, ContextMeter::to_json);
    // The model's own text, completed: any resolved reference row it left
    // out is added, and a literal ANSWER marker is guaranteed, so a caller
    // recording this run's answer never comes back with nothing under it.
    let final_text = compose_final_answer(final_text, &counters.reference_rows);
    let record = writer.result(
        status.subtype(),
        status != ExitStatus::Success,
        counters.turns,
        started.elapsed().as_millis(),
        counters.api_ms,
        &final_text,
        counters.usage_json(),
        agent,
    )?;
    std::fs::write(
        config.out_dir.join("result.json"),
        serde_json::to_string_pretty(&record)?,
    )?;
    Ok(RunOutcome {
        status,
        final_text,
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
                    "trust_reason": "coverage_partial: python bodies are not indexed",
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
                    "trust_reason": "coverage_partial: python bodies are not indexed",
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

#[cfg(test)]
mod reference_rows_tests {
    use super::*;

    /// Trimmed from the real `find_references` result a T1 study task's
    /// `toSSG` query returned: six rows, every one `resolution:
    /// "type_resolved"`, two of them (`bun/ssg.ts`, `deno/ssg.ts`, both
    /// `kind: "Module"`) attributed to the aliased-import lines the task was
    /// built to require. The model's own final ANSWER text kept four of the
    /// six and dropped exactly those two, even though nothing about them was
    /// less certain than the four it kept.
    const TOSSG_FIND_REFERENCES_RESULT: &str = r#"{
        "focal_entity": {"id": "9407382b-fdc1-42b6-a0b8-3944d23daed1", "name": "toSSG"},
        "references": [
            {"entity_id": "ade70b82-85aa-4f01-8291-b5f1955f094d", "file_path": "src/adapter/bun/ssg.ts", "kind": "Module", "name": "ssg", "reference_lines": [2], "resolution": "type_resolved", "role": "source"},
            {"entity_id": "84ef6563-5c14-41da-9a96-3a962c025845", "file_path": "src/adapter/bun/ssg.ts", "kind": "Function", "name": "toSSG", "reference_lines": [26], "resolution": "type_resolved", "role": "source"},
            {"entity_id": "dee91665-f43c-4025-a5c4-19f9ee5ac89a", "file_path": "src/adapter/deno/ssg.ts", "kind": "Module", "name": "ssg", "reference_lines": [1], "resolution": "type_resolved", "role": "source"},
            {"entity_id": "f7d3013b-7853-4f2f-8509-4880542c0f65", "file_path": "src/adapter/deno/ssg.ts", "kind": "Function", "name": "toSSG", "reference_lines": [26], "resolution": "type_resolved", "role": "source"},
            {"entity_id": "5e662ffe-3ec6-4cf7-84a0-410f63e86e14", "file_path": "src/helper/ssg/plugins.test.tsx", "kind": "Module", "name": "plugins.test", "reference_lines": [4, 32], "resolution": "type_resolved", "role": "test"},
            {"entity_id": "b5a9d3b0-4d6d-47f7-b159-c9f772c6109d", "file_path": "src/helper/ssg/ssg.test.tsx", "kind": "Module", "name": "ssg.test", "reference_lines": [12], "resolution": "type_resolved", "role": "test"}
        ]
    }"#;

    /// The exact defect: Kin returned six correctly `type_resolved` rows and
    /// the model's own prose kept only four, dropping the two `Module`-kind
    /// source rows while keeping two more `Module`-kind rows from test files.
    /// No code in this crate touches row content by kind (see the field's own
    /// doc comment on `Counters::reference_rows`), so the belt cannot make
    /// the model keep all six in its prose. It can still make all six
    /// available to a consumer that does not read the prose: this asserts
    /// that every row Kin returned survives into the structured record,
    /// including the two the model's own answer text would have dropped.
    #[test]
    fn every_type_resolved_row_survives_regardless_of_kind() {
        let mut counters = Counters::new();
        counters.record_reference_rows("find_references", TOSSG_FIND_REFERENCES_RESULT);

        let agent = counters.to_json(0, &Stop::new(ExitStatus::Success, "final_answer", None));
        let rows = agent["reference_rows"]
            .as_array()
            .expect("reference_rows must be an array");
        assert_eq!(rows.len(), 6, "expected all six rows, got: {rows:#?}");

        let kept_by_a_model_that_drops_module_kind_source_rows =
            ["src/adapter/bun/ssg.ts", "src/adapter/deno/ssg.ts"];
        for file in kept_by_a_model_that_drops_module_kind_source_rows {
            let module_row = rows
                .iter()
                .find(|row| row["file_path"] == file && row["kind"] == "Module");
            assert!(
                module_row.is_some(),
                "the Module-kind row for {file} must survive into the structured record even \
                 though a model's own prose dropped it: {rows:#?}"
            );
            assert_eq!(module_row.unwrap()["resolution"], "type_resolved");
        }
    }

    /// A result from any other tool is not `find_references`-shaped and must
    /// add nothing, so a consumer never sees, say, `get_entity_source` bodies
    /// misread as reference rows.
    #[test]
    fn a_result_from_a_different_tool_is_ignored() {
        let mut counters = Counters::new();
        counters.record_reference_rows("get_entity_source", TOSSG_FIND_REFERENCES_RESULT);
        let agent = counters.to_json(0, &Stop::new(ExitStatus::Success, "final_answer", None));
        assert_eq!(agent["reference_rows"].as_array().unwrap().len(), 0);
    }

    /// Text that is not the expected JSON shape, or not JSON at all, must not
    /// panic the run; it is read best-effort and adds nothing on a miss.
    #[test]
    fn malformed_or_unrelated_text_is_read_best_effort() {
        let mut counters = Counters::new();
        counters.record_reference_rows("find_references", "not json at all");
        counters.record_reference_rows("find_references", r#"{"message": "Entity not found"}"#);
        let agent = counters.to_json(0, &Stop::new(ExitStatus::Success, "final_answer", None));
        assert_eq!(agent["reference_rows"].as_array().unwrap().len(), 0);
    }

    /// A second `find_references` call in the same run, naming the same
    /// focal and referenced entity, merges onto one row rather than
    /// duplicating it, the way a multi-turn run that re-asks the same
    /// question would.
    #[test]
    fn a_repeated_call_merges_rather_than_duplicates() {
        let mut counters = Counters::new();
        counters.record_reference_rows("find_references", TOSSG_FIND_REFERENCES_RESULT);
        counters.record_reference_rows("find_references", TOSSG_FIND_REFERENCES_RESULT);
        let agent = counters.to_json(0, &Stop::new(ExitStatus::Success, "final_answer", None));
        assert_eq!(agent["reference_rows"].as_array().unwrap().len(), 6);
    }
}

#[cfg(test)]
mod final_answer_tests {
    use super::*;

    /// A minimal `find_references` result: four resolved rows, two of them
    /// aliased-import lines (`kind: "Module"`), the same shape and the same
    /// line numbers a study task handed the belt. Line 2 and line 26 on the
    /// same path are deliberately both present, so a naive substring check
    /// for "is line 2 already in the text" would wrongly match inside "26".
    /// This fixture doubles as a regression guard for that.
    const FOUR_RESOLVED_ROWS: &str = r#"{
        "focal_entity": {"id": "9407382b-fdc1-42b6-a0b8-3944d23daed1", "name": "toSSG"},
        "references": [
            {"entity_id": "ade70b82-85aa-4f01-8291-b5f1955f094d", "file_path": "src/adapter/bun/ssg.ts", "kind": "Module", "name": "ssg", "reference_lines": [2], "resolution": "type_resolved", "role": "source"},
            {"entity_id": "84ef6563-5c14-41da-9a96-3a962c025845", "file_path": "src/adapter/bun/ssg.ts", "kind": "Function", "name": "toSSG", "reference_lines": [26], "resolution": "type_resolved", "role": "source"},
            {"entity_id": "dee91665-f43c-4025-a5c4-19f9ee5ac89a", "file_path": "src/adapter/deno/ssg.ts", "kind": "Module", "name": "ssg", "reference_lines": [1], "resolution": "type_resolved", "role": "source"},
            {"entity_id": "f7d3013b-7853-4f2f-8509-4880542c0f65", "file_path": "src/adapter/deno/ssg.ts", "kind": "Function", "name": "toSSG", "reference_lines": [26], "resolution": "type_resolved", "role": "source"}
        ]
    }"#;

    /// The exact defect: the belt kept the two `Function`-kind rows and
    /// dropped the two `Module`-kind aliased-import rows, even though
    /// `find_references` resolved all four with equal confidence. The
    /// composed answer must carry all four, not just the two the model's
    /// own prose kept: an import line is a reference like any other.
    #[test]
    fn missing_resolved_rows_including_import_lines_are_added_to_the_answer() {
        let mut counters = Counters::new();
        counters.record_reference_rows("find_references", FOUR_RESOLVED_ROWS);
        let model_text = "```ANSWER\nsrc/adapter/bun/ssg.ts:26\nsrc/adapter/deno/ssg.ts:26\n```";

        let composed = compose_final_answer(model_text, &counters.reference_rows);

        let rows: Vec<&str> = composed
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !is_answer_marker_line(line) && *line != "```")
            .collect();
        assert_eq!(rows.len(), 4, "expected four answer rows, got: {rows:?}");
        for expected in [
            "src/adapter/bun/ssg.ts:2",
            "src/adapter/bun/ssg.ts:26",
            "src/adapter/deno/ssg.ts:1",
            "src/adapter/deno/ssg.ts:26",
        ] {
            assert!(
                rows.contains(&expected),
                "the answer must carry {expected}, an import line is a reference like any \
                 other: {composed}"
            );
        }
    }

    /// A run whose model produced no final text at all still reports an
    /// answer a caller can find: the block is emitted and says plainly that
    /// the run had nothing to put in it.
    #[test]
    fn an_empty_model_answer_still_carries_the_answer_block() {
        let counters = Counters::new();
        let composed = compose_final_answer("", &counters.reference_rows);
        assert!(
            composed.lines().any(is_answer_marker_line),
            "an empty answer must still carry the marker: {composed:?}"
        );
        assert!(
            composed.to_ascii_lowercase().contains("empty"),
            "an empty answer must say so inside the block: {composed:?}"
        );
    }

    /// The exact other defect: the model wrote the complete, correct row
    /// list inside a bare fence with no literal `ANSWER` token anywhere, so
    /// a caller parsing for the marker found nothing even though the rows
    /// underneath were exactly right.
    #[test]
    fn a_bare_fenced_list_gains_the_marker_without_losing_its_rows() {
        let counters = Counters::new();
        let model_text = "The method is referenced in the following places:\n\n\
                           ```\ntests/test_blueprints.py:899\ntests/test_blueprints.py:900\n```";

        let composed = compose_final_answer(model_text, &counters.reference_rows);

        assert!(
            composed.lines().any(is_answer_marker_line),
            "a bare fenced list must gain the marker: {composed:?}"
        );
        for expected in [
            "tests/test_blueprints.py:899",
            "tests/test_blueprints.py:900",
        ] {
            assert!(
                composed.contains(expected),
                "relabelling the fence must not lose {expected}: {composed}"
            );
        }
    }

    /// The no-op path: an answer that already carries the marker and
    /// already names every resolved row is returned byte-for-byte
    /// unchanged, and so is an ordinary conversational answer with no
    /// marker, nothing missing, and no line shaped like a position. A plain
    /// reply is never forced into a fence it never needed.
    #[test]
    fn an_already_complete_answer_and_plain_prose_are_left_unchanged() {
        let mut counters = Counters::new();
        counters.record_reference_rows("find_references", FOUR_RESOLVED_ROWS);
        let complete = "```ANSWER\nsrc/adapter/bun/ssg.ts:2\nsrc/adapter/bun/ssg.ts:26\n\
                         src/adapter/deno/ssg.ts:1\nsrc/adapter/deno/ssg.ts:26\n```";
        assert_eq!(
            compose_final_answer(complete, &counters.reference_rows),
            complete
        );

        let empty_counters = Counters::new();
        let prose = "greet is defined in src/greet.py and now carries a docstring.";
        assert_eq!(
            compose_final_answer(prose, &empty_counters.reference_rows),
            prose
        );
    }
}

#[cfg(test)]
mod reserve_tests {
    use super::parse_output_reserve;
    #[test]
    fn output_reserve_environment_value_requires_a_positive_integer() {
        for value in ["", "0", "-1", "1.5", "18446744073709551616", "unlimited"] {
            assert!(parse_output_reserve(value).is_err(), "{value}");
        }
        assert_eq!(parse_output_reserve("32768").unwrap(), 32768);
    }
}

#[cfg(test)]
mod guidance_tests {
    use super::*;

    fn kin_tool(bare: &str) -> belt::KinTool {
        belt::KinTool {
            folded: false,
            server: 0,
            bare: bare.to_string(),
            exposed: format!("{}{bare}", belt::KIN_TOOL_PREFIX),
            description: format!("test tool {bare}"),
            schema: json!({ "type": "object" }),
        }
    }

    /// The change guidance addresses the entity by its UUID, carries the source_base Kin
    /// returned, prefers the anchored patch over a whole body, offers only the lifecycle
    /// `kin_mutate` serves, and leaves the session to the harness that opened it.
    #[test]
    fn the_change_guidance_is_entity_addressed_and_source_bound() {
        let prompt = DEFAULT_SYSTEM_PROMPT;
        for expected in [
            "name the entity you are changing by its UUID",
            "Prefer verb 'patch' with target set to that UUID",
            "EntitySourcePatch payload: the exact source_base",
            "use verb 'update' with target set to its UUID, an EntitySourceBase payload holding \
             that same exact source_base, and body set to its complete new source text",
            "Every update must carry that EntitySourceBase, and one without it is refused",
            "verb 'create' with target set to an existing function's UUID and an EntityCreate \
             payload",
            "verb 'remove' with its UUID and an EntityRemove payload holding its source_base",
            "Use only these operations, as the mcp__kin__kin_mutate schema describes them.",
            "Your session is already open",
            "there is no file creation",
            "If the change needs something kin_mutate cannot make, stop and say so.",
        ] {
            assert!(prompt.contains(expected), "the prompt lost {expected:?}");
        }
        let patch = prompt.find("Prefer verb 'patch'").unwrap();
        let update = prompt.find("verb 'update'").unwrap();
        assert!(
            patch < update,
            "the patch comes first and the whole body second"
        );
        // The session tools are the harness's and never on the belt, so the prompt must
        // not send the model looking for one.
        assert!(!prompt.contains("kin_session_start"));
    }

    /// A model that reaches for a retired file tool is given the same guidance.
    #[test]
    fn a_file_tool_refusal_carries_the_entity_guidance() {
        let belt = Belt::new(vec![kin_tool("kin_mutate"), kin_tool("get_entity_source")]);
        for name in ["edit_file", "write_file"] {
            let Route::Refused(refusal) = belt.route(name) else {
                panic!("{name} must be refused");
            };
            for expected in [
                "`mcp__kin__kin_mutate`, naming the entity by its UUID",
                "the exact source_base `mcp__kin__get_entity_source` returned",
                "Prefer verb 'patch' with an EntitySourcePatch",
                "verb 'create' and an EntityCreate payload",
                "verb 'remove' and an EntityRemove payload",
                "There is no file creation.",
                "stop and say so",
            ] {
                assert!(
                    refusal.contains(expected),
                    "{name}: lost {expected:?}: {refusal}"
                );
            }
            assert!(
                !refusal.contains("complete new source body"),
                "{name}: the whole body is no longer the first advice: {refusal}"
            );
        }
    }
}

#[cfg(test)]
mod session_retry_tests {
    use super::*;

    fn refused(text: &str) -> ToolOutcome {
        ToolOutcome {
            text: text.to_string(),
            is_error: true,
            envelope: None,
            negative: None,
            unreadable: false,
            wall_ms: 1,
        }
    }

    fn marked(stage: &str, refusal: &str, session: &str) -> ToolOutcome {
        refused(&format!(
            "kin_mutate_not_started: {}\nSession not found: {session}. It was ended.",
            json!({ "stage": stage, "refusal": refusal, "session_id": session })
        ))
    }

    /// The text as a Kin server delivers a refusal: inside the envelope.
    fn enveloped(text: &str) -> ToolOutcome {
        refused(
            &json!({
                "_kin": { "envelope_version": 2, "runtime": "repo-daemon" },
                "message": text,
            })
            .to_string(),
        )
    }

    /// The marker reaches the run inside the envelope's `message`, which is how the begin
    /// refusal arrived after a real daemon restart, and it is read from there by the same
    /// rules. The envelope never lends the marker anything the raw text would not.
    #[test]
    fn a_marker_inside_the_envelope_message_is_read_by_the_same_rules() {
        let unsessioned = json!({ "operations": [] });
        let gone = marked("begin", "session_not_found", "sess-1");
        assert!(retry_under_fresh_session(
            "kin_mutate",
            &unsessioned,
            &enveloped(&gone.text),
            Some("sess-1")
        ));

        let note = "connection reset by peer\n\nkin_mutate could not abort transaction txn-1 \
                    after its commit failed (Session not found: sess-1. It was ended.), so that \
                    transaction is still open.";
        let late = "refused\nkin_mutate_not_started: {\"stage\":\"begin\",\"refusal\":\
                    \"session_not_found\",\"session_id\":\"sess-1\"}";
        for outcome in [
            enveloped(&marked("begin", "session_not_found", "sess-9").text),
            enveloped(&marked("commit", "session_not_found", "sess-1").text),
            enveloped(note),
            enveloped(late),
            // The marker in some other field of the payload is not the refusal's first line.
            refused(
                &json!({ "_kin": { "envelope_version": 2 }, "detail": gone.text.clone() })
                    .to_string(),
            ),
        ] {
            assert!(
                !retry_under_fresh_session("kin_mutate", &unsessioned, &outcome, Some("sess-1")),
                "{}",
                outcome.text
            );
        }
        // A model-named session stays the model's, enveloped or not.
        let named = json!({ "operations": [], "session_id": "sess-1" });
        assert!(!retry_under_fresh_session(
            "kin_mutate",
            &named,
            &enveloped(&gone.text),
            Some("sess-1")
        ));
    }

    /// Only an unkeyed `kin_mutate` the harness sessioned, whose first line marks a begin
    /// refused because the harness's own session is gone, is sent again.
    #[test]
    fn only_a_begin_marked_not_started_for_this_session_is_retried() {
        let unsessioned = json!({ "operations": [] });
        let gone = marked("begin", "session_not_found", "sess-1");
        assert!(retry_under_fresh_session(
            "kin_mutate",
            &unsessioned,
            &gone,
            Some("sess-1")
        ));
        // A blank session is no session, so the harness supplied the one that went.
        let blank = json!({ "operations": [], "session_id": "  " });
        assert!(retry_under_fresh_session(
            "kin_mutate",
            &blank,
            &gone,
            Some("sess-1")
        ));

        // The model named the session or keyed the call; the run holds no session; the
        // marker names another session, another stage or another refusal.
        let named = json!({ "operations": [], "session_id": "sess-1" });
        let keyed = json!({ "operations": [], "request_id": "req-1" });
        for (sent, outcome, session) in [
            (&named, &gone, Some("sess-1")),
            (&keyed, &gone, Some("sess-1")),
            (&unsessioned, &gone, None),
            (
                &unsessioned,
                &marked("begin", "session_not_found", "sess-9"),
                Some("sess-1"),
            ),
            (
                &unsessioned,
                &marked("commit", "session_not_found", "sess-1"),
                Some("sess-1"),
            ),
            (
                &unsessioned,
                &marked("begin", "read_only_session", "sess-1"),
                Some("sess-1"),
            ),
        ] {
            assert!(
                !retry_under_fresh_session("kin_mutate", sent, outcome, session),
                "{sent} {} {session:?}",
                outcome.text
            );
        }

        // The words anywhere but as the first-line marker are never enough: the abort
        // note after an unanswered commit, a commit refusal, or the marker after a line.
        for text in [
            "connection reset by peer\n\nkin_mutate could not abort transaction txn-1 after \
             its commit failed (Session not found: sess-1. It was ended.), so that transaction \
             is still open.",
            "Session not found: sess-1. It was ended or expired after its idle timeout.",
            "refused\nkin_mutate_not_started: {\"stage\":\"begin\",\"refusal\":\
             \"session_not_found\",\"session_id\":\"sess-1\"}",
        ] {
            assert!(
                !retry_under_fresh_session(
                    "kin_mutate",
                    &unsessioned,
                    &refused(text),
                    Some("sess-1")
                ),
                "{text}"
            );
        }

        // Any other tool, or a clean answer, is left as it is.
        assert!(!retry_under_fresh_session(
            "get_entity_source",
            &unsessioned,
            &gone,
            Some("sess-1")
        ));
        let clean = ToolOutcome {
            is_error: false,
            ..marked("begin", "session_not_found", "sess-1")
        };
        assert!(!retry_under_fresh_session(
            "kin_mutate",
            &unsessioned,
            &clean,
            Some("sess-1")
        ));
    }
}
