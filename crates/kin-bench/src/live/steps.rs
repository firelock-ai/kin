use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::runner::TimedLineEvent;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    CommandExecution,
    McpToolCall,
    SubagentTask,
    AgentMessage,
    ThreadStarted,
    TurnStarted,
    TurnCompleted,
    Result,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepTraceEntry {
    pub sequence: usize,
    pub item_id: Option<String>,
    pub parent_item_id: Option<String>,
    pub kind: StepKind,
    pub raw_type: String,
    pub label: String,
    pub status: Option<String>,
    pub exit_code: Option<i64>,
    pub started_offset_ms: Option<f64>,
    pub ended_offset_ms: Option<f64>,
    pub duration_ms: Option<f64>,
    pub output_chars: usize,
    pub output_tokens_est: u64,
    #[serde(default)]
    pub turn_input_tokens: u64,
    #[serde(default)]
    pub turn_output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepHotspot {
    pub label: String,
    pub kind: StepKind,
    pub duration_ms: Option<f64>,
    pub output_chars: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubagentTraceSummary {
    pub item_id: Option<String>,
    pub label: String,
    pub duration_ms: Option<f64>,
    pub child_steps: usize,
    pub child_command_steps: usize,
    pub child_mcp_steps: usize,
    pub child_output_chars: usize,
    pub child_output_tokens_est: u64,
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub total_tokens: u64,
    #[serde(default)]
    pub estimated_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepTraceSummary {
    pub total_steps: usize,
    pub command_steps: usize,
    pub mcp_steps: usize,
    pub subagent_steps: usize,
    pub agent_message_steps: usize,
    pub failed_steps: usize,
    pub total_output_chars: usize,
    pub total_output_tokens_est: u64,
    pub has_precise_timing: bool,
    pub top_by_duration: Vec<StepHotspot>,
    pub top_by_output: Vec<StepHotspot>,
    pub subagents: Vec<SubagentTraceSummary>,
    #[serde(default)]
    pub main_agent_input_tokens: u64,
    #[serde(default)]
    pub main_agent_output_tokens: u64,
    #[serde(default)]
    pub main_agent_total_tokens: u64,
    #[serde(default)]
    pub main_agent_cost_usd: f64,
    #[serde(default)]
    pub subagent_total_input_tokens: u64,
    #[serde(default)]
    pub subagent_total_output_tokens: u64,
    #[serde(default)]
    pub subagent_total_tokens: u64,
    #[serde(default)]
    pub subagent_total_cost_usd: f64,
    #[serde(default)]
    pub unattributed_total_tokens: u64,
    #[serde(default)]
    pub unattributed_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepTrace {
    pub entries: Vec<StepTraceEntry>,
    pub summary: StepTraceSummary,
}

#[derive(Debug, Clone)]
struct PendingStep {
    kind: StepKind,
    label: String,
    started_offset_ms: f64,
}

#[derive(Debug, Clone, Default)]
struct UsageAttribution {
    parent_item_id: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
}

pub fn extract_step_trace(events: &[TimedLineEvent]) -> StepTrace {
    let mut entries = Vec::new();
    let mut pending: HashMap<String, PendingStep> = HashMap::new();
    let mut usage_by_message: HashMap<String, UsageAttribution> = HashMap::new();

    for event in events {
        let Ok(v) = serde_json::from_str::<Value>(&event.line) else {
            continue;
        };

        let raw_type = v
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown")
            .to_string();

        let raw_type_key = raw_type.clone();
        match raw_type_key.as_str() {
            "item.started" => {
                if let Some(item) = v.get("item") {
                    if let Some(item_id) = item.get("id").and_then(|id| id.as_str()) {
                        let kind = step_kind_for_item(item);
                        let label = step_label_for_item(item);
                        pending.insert(
                            item_id.to_string(),
                            PendingStep {
                                kind,
                                label,
                                started_offset_ms: event.offset_ms,
                            },
                        );
                    }
                }
            }
            "item.completed" => {
                if let Some(item) = v.get("item") {
                    let item_id = item
                        .get("id")
                        .and_then(|id| id.as_str())
                        .map(|s| s.to_string());
                    let default_kind = step_kind_for_item(item);
                    let default_label = step_label_for_item(item);
                    let pending_step = item_id
                        .as_ref()
                        .and_then(|id| pending.remove(id))
                        .unwrap_or(PendingStep {
                            kind: default_kind,
                            label: default_label,
                            started_offset_ms: event.offset_ms,
                        });

                    let output = step_output_for_item(item);
                    entries.push(StepTraceEntry {
                        sequence: entries.len(),
                        item_id,
                        parent_item_id: None,
                        kind: pending_step.kind,
                        raw_type,
                        label: pending_step.label,
                        status: item
                            .get("status")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string()),
                        exit_code: item.get("exit_code").and_then(|c| c.as_i64()),
                        started_offset_ms: Some(pending_step.started_offset_ms),
                        ended_offset_ms: Some(event.offset_ms),
                        duration_ms: Some((event.offset_ms - pending_step.started_offset_ms).max(0.0)),
                        output_chars: output.len(),
                        output_tokens_est: estimate_tokens(output.len()),
                        turn_input_tokens: 0,
                        turn_output_tokens: 0,
                    });
                }
            }
            "thread.started" => entries.push(simple_entry(
                entries.len(),
                StepKind::ThreadStarted,
                raw_type,
                "thread.started".to_string(),
                event.offset_ms,
            )),
            "turn.started" => entries.push(simple_entry(
                entries.len(),
                StepKind::TurnStarted,
                raw_type,
                "turn.started".to_string(),
                event.offset_ms,
            )),
            "turn.completed" => {
                let (input_tokens, output_tokens) =
                    if let Some(usage) = v.get("usage") {
                        (
                            usage
                                .get("input_tokens")
                                .and_then(|n| n.as_u64())
                                .unwrap_or(0),
                            usage
                                .get("output_tokens")
                                .and_then(|n| n.as_u64())
                                .unwrap_or(0),
                        )
                    } else {
                        (0, 0)
                    };
                let label = if input_tokens > 0 || output_tokens > 0 {
                    format!(
                        "turn.completed ({} in / {} out tokens)",
                        input_tokens, output_tokens
                    )
                } else {
                    "turn.completed".to_string()
                };
                let parent_item_id = v
                    .get("parent_tool_use_id")
                    .and_then(|id| id.as_str())
                    .map(|s| s.to_string());
                entries.push(StepTraceEntry {
                    sequence: entries.len(),
                    item_id: None,
                    parent_item_id,
                    kind: StepKind::TurnCompleted,
                    raw_type,
                    label,
                    status: None,
                    exit_code: None,
                    started_offset_ms: None,
                    ended_offset_ms: Some(event.offset_ms),
                    duration_ms: None,
                    output_chars: 0,
                    output_tokens_est: 0,
                    turn_input_tokens: input_tokens,
                    turn_output_tokens: output_tokens,
                });
            }
            "result" => {
                let output = v
                    .get("result")
                    .and_then(|r| r.as_str())
                    .unwrap_or_default();
                entries.push(StepTraceEntry {
                    sequence: entries.len(),
                    item_id: None,
                    parent_item_id: None,
                    kind: StepKind::Result,
                    raw_type,
                    label: "result".to_string(),
                    status: v
                        .get("subtype")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string()),
                    exit_code: None,
                    started_offset_ms: None,
                    ended_offset_ms: Some(event.offset_ms),
                    duration_ms: v.get("duration_ms").and_then(|d| d.as_f64()),
                    output_chars: output.len(),
                    output_tokens_est: estimate_tokens(output.len()),
                    turn_input_tokens: 0,
                    turn_output_tokens: 0,
                });
            }
            "assistant" => handle_claude_assistant_event(
                &v,
                event,
                &mut entries,
                &mut pending,
                &mut usage_by_message,
            ),
            "user" => handle_claude_user_event(&v, event, &mut entries, &mut pending),
            other => entries.push(simple_entry(
                entries.len(),
                StepKind::Other,
                raw_type,
                other.to_string(),
                event.offset_ms,
            )),
        }
    }

    let summary = summarize(&entries, &usage_by_message);
    StepTrace { entries, summary }
}

fn handle_claude_assistant_event(
    v: &Value,
    event: &TimedLineEvent,
    entries: &mut Vec<StepTraceEntry>,
    pending: &mut HashMap<String, PendingStep>,
    usage_by_message: &mut HashMap<String, UsageAttribution>,
) {
    let parent_item_id = v
        .get("parent_tool_use_id")
        .and_then(|id| id.as_str())
        .map(|s| s.to_string());
    if let Some(message_id) = v
        .get("message")
        .and_then(|m| m.get("id"))
        .and_then(|id| id.as_str())
    {
        let (input_tokens, output_tokens) = message_usage_totals(v);
        usage_by_message.insert(
            message_id.to_string(),
            UsageAttribution {
                parent_item_id: parent_item_id.clone(),
                input_tokens,
                output_tokens,
            },
        );
    }
    let Some(content) = v
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
    else {
        entries.push(simple_entry(
            entries.len(),
            StepKind::Other,
            "assistant".to_string(),
            "assistant".to_string(),
            event.offset_ms,
        ));
        return;
    };

    for item in content {
        match item.get("type").and_then(|t| t.as_str()).unwrap_or("other") {
            "tool_use" => {
                let item_id = item
                    .get("id")
                    .and_then(|id| id.as_str())
                    .unwrap_or_default()
                    .to_string();
                if item_id.is_empty() {
                    continue;
                }
                pending.insert(
                    item_id,
                    PendingStep {
                        kind: step_kind_for_claude_tool(item),
                        label: step_label_for_claude_tool(item),
                        started_offset_ms: event.offset_ms,
                    },
                );
            }
            "text" | "thinking" => {
                let output = item
                    .get("text")
                    .or_else(|| item.get("thinking"))
                    .and_then(|t| t.as_str())
                    .unwrap_or_default();
                entries.push(StepTraceEntry {
                    sequence: entries.len(),
                    item_id: None,
                    parent_item_id: parent_item_id.clone(),
                    kind: StepKind::AgentMessage,
                    raw_type: "assistant".to_string(),
                    label: shorten(output),
                    status: None,
                    exit_code: None,
                    started_offset_ms: None,
                    ended_offset_ms: Some(event.offset_ms),
                    duration_ms: None,
                    output_chars: output.len(),
                    output_tokens_est: estimate_tokens(output.len()),
                    turn_input_tokens: 0,
                    turn_output_tokens: 0,
                });
            }
            other => entries.push(simple_entry(
                entries.len(),
                StepKind::Other,
                "assistant".to_string(),
                format!("assistant.{other}"),
                event.offset_ms,
            )),
        }
    }
}

fn handle_claude_user_event(
    v: &Value,
    event: &TimedLineEvent,
    entries: &mut Vec<StepTraceEntry>,
    pending: &mut HashMap<String, PendingStep>,
) {
    let parent_item_id = v
        .get("parent_tool_use_id")
        .and_then(|id| id.as_str())
        .map(|s| s.to_string());
    let Some(content) = v
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
    else {
        entries.push(simple_entry(
            entries.len(),
            StepKind::Other,
            "user".to_string(),
            "user".to_string(),
            event.offset_ms,
        ));
        return;
    };

    for item in content {
        if item.get("type").and_then(|t| t.as_str()) != Some("tool_result") {
            entries.push(simple_entry(
                entries.len(),
                StepKind::Other,
                "user".to_string(),
                "user".to_string(),
                event.offset_ms,
            ));
            continue;
        }

        let item_id = item
            .get("tool_use_id")
            .and_then(|id| id.as_str())
            .map(|s| s.to_string());
        let pending_step = item_id
            .as_ref()
            .and_then(|id| pending.remove(id))
            .unwrap_or(PendingStep {
                kind: StepKind::Other,
                label: "tool_result".to_string(),
                started_offset_ms: event.offset_ms,
            });
        let output = step_output_for_claude_tool_result(v, item);
        entries.push(StepTraceEntry {
            sequence: entries.len(),
            item_id,
            parent_item_id: parent_item_id.clone(),
            kind: pending_step.kind,
            raw_type: "user".to_string(),
            label: pending_step.label,
            status: Some(
                if item
                    .get("is_error")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false)
                {
                    "failed"
                } else {
                    "completed"
                }
                .to_string(),
            ),
            exit_code: None,
            started_offset_ms: Some(pending_step.started_offset_ms),
            ended_offset_ms: Some(event.offset_ms),
            duration_ms: Some((event.offset_ms - pending_step.started_offset_ms).max(0.0)),
            output_chars: output.len(),
            output_tokens_est: estimate_tokens(output.len()),
            turn_input_tokens: 0,
            turn_output_tokens: 0,
        });
    }
}

fn simple_entry(
    sequence: usize,
    kind: StepKind,
    raw_type: String,
    label: String,
    offset_ms: f64,
) -> StepTraceEntry {
    StepTraceEntry {
        sequence,
        item_id: None,
        parent_item_id: None,
        kind,
        raw_type,
        label,
        status: None,
        exit_code: None,
        started_offset_ms: None,
        ended_offset_ms: Some(offset_ms),
        duration_ms: None,
        output_chars: 0,
        output_tokens_est: 0,
        turn_input_tokens: 0,
        turn_output_tokens: 0,
    }
}

fn step_kind_for_item(item: &Value) -> StepKind {
    match item.get("type").and_then(|t| t.as_str()).unwrap_or("other") {
        "command_execution" => StepKind::CommandExecution,
        "mcp_tool_call" => StepKind::McpToolCall,
        "agent_message" => StepKind::AgentMessage,
        _ => StepKind::Other,
    }
}

fn step_label_for_item(item: &Value) -> String {
    match item.get("type").and_then(|t| t.as_str()).unwrap_or("other") {
        "command_execution" => item
            .get("command")
            .and_then(|c| c.as_str())
            .unwrap_or("command_execution")
            .to_string(),
        "mcp_tool_call" => {
            let server = item.get("server").and_then(|s| s.as_str()).unwrap_or("mcp");
            let tool = item.get("tool").and_then(|s| s.as_str()).unwrap_or("tool");
            format!("{server}::{tool}")
        }
        "agent_message" => item
            .get("text")
            .and_then(|t| t.as_str())
            .map(shorten)
            .unwrap_or_else(|| "agent_message".to_string()),
        _ => item
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("other")
            .to_string(),
    }
}

fn step_output_for_item(item: &Value) -> String {
    if let Some(text) = item.get("aggregated_output").and_then(|t| t.as_str()) {
        if !text.is_empty() {
            return text.to_string();
        }
    }
    if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
        return text.to_string();
    }
    if let Some(result) = item.get("result") {
        if let Ok(serialized) = serde_json::to_string(result) {
            return serialized;
        }
    }
    String::new()
}

fn step_kind_for_claude_tool(item: &Value) -> StepKind {
    match item.get("name").and_then(|n| n.as_str()).unwrap_or("other") {
        "Agent" | "Task" | "TaskOutput" => StepKind::SubagentTask,
        "Bash" | "Read" | "Grep" | "Glob" => StepKind::CommandExecution,
        name if name.starts_with("mcp__") => StepKind::McpToolCall,
        _ => StepKind::Other,
    }
}

fn step_label_for_claude_tool(item: &Value) -> String {
    let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
    let input = item.get("input").unwrap_or(&Value::Null);
    match name {
        "Bash" => input
            .get("command")
            .and_then(|c| c.as_str())
            .map(shorten)
            .unwrap_or_else(|| "Bash".to_string()),
        "Read" => input
            .get("file_path")
            .and_then(|p| p.as_str())
            .map(|p| format!("Read {p}"))
            .unwrap_or_else(|| "Read".to_string()),
        "Grep" => input
            .get("pattern")
            .and_then(|p| p.as_str())
            .map(|p| format!("Grep {p}"))
            .unwrap_or_else(|| "Grep".to_string()),
        "Glob" => input
            .get("pattern")
            .and_then(|p| p.as_str())
            .map(|p| format!("Glob {p}"))
            .unwrap_or_else(|| "Glob".to_string()),
        "Agent" | "Task" => {
            let subagent = input
                .get("subagent_type")
                .or_else(|| input.get("subagent"))
                .and_then(|s| s.as_str());
            let description = input
                .get("description")
                .and_then(|d| d.as_str())
                .or_else(|| input.get("prompt").and_then(|p| p.as_str()))
                .map(shorten)
                .unwrap_or_else(|| "subagent task".to_string());
            match subagent {
                Some(name) => format!("Subagent {name}: {description}"),
                None => format!("Subagent: {description}"),
            }
        }
        other => other.to_string(),
    }
}

fn step_output_for_claude_tool_result(v: &Value, item: &Value) -> String {
    if let Some(text) = item.get("content").and_then(|c| c.as_str()) {
        return text.to_string();
    }
    if let Some(tool_result) = v.get("tool_use_result") {
        if let Some(stdout) = tool_result.get("stdout").and_then(|s| s.as_str()) {
            if !stdout.is_empty() {
                return stdout.to_string();
            }
        }
        if let Some(stderr) = tool_result.get("stderr").and_then(|s| s.as_str()) {
            if !stderr.is_empty() {
                return stderr.to_string();
            }
        }
        if let Ok(serialized) = serde_json::to_string(tool_result) {
            return serialized;
        }
    }
    String::new()
}

/// Rough per-token cost estimate (USD). This is a simple approximation;
/// real cost comes from the provider's result event.
const COST_PER_TOKEN_USD: f64 = 0.000003;

fn summarize(
    entries: &[StepTraceEntry],
    usage_by_message: &HashMap<String, UsageAttribution>,
) -> StepTraceSummary {
    let command_steps = entries
        .iter()
        .filter(|e| e.kind == StepKind::CommandExecution)
        .count();
    let mcp_steps = entries
        .iter()
        .filter(|e| e.kind == StepKind::McpToolCall)
        .count();
    let subagent_steps = entries
        .iter()
        .filter(|e| e.kind == StepKind::SubagentTask)
        .count();
    let agent_message_steps = entries
        .iter()
        .filter(|e| e.kind == StepKind::AgentMessage)
        .count();
    let failed_steps = entries
        .iter()
        .filter(|e| {
            e.status.as_deref() == Some("failed")
                || e.exit_code.map(|c| c != 0).unwrap_or(false)
        })
        .count();
    let total_output_chars = entries.iter().map(|e| e.output_chars).sum();
    let total_output_tokens_est = entries.iter().map(|e| e.output_tokens_est).sum();
    let has_precise_timing = entries.iter().any(|e| e.duration_ms.is_some());

    let mut by_duration: Vec<StepHotspot> = entries
        .iter()
        .filter(|e| e.duration_ms.is_some())
        .map(|e| StepHotspot {
            label: e.label.clone(),
            kind: e.kind.clone(),
            duration_ms: e.duration_ms,
            output_chars: e.output_chars,
        })
        .collect();
    by_duration.sort_by(|a, b| {
        b.duration_ms
            .partial_cmp(&a.duration_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    by_duration.truncate(5);

    let mut by_output: Vec<StepHotspot> = entries
        .iter()
        .map(|e| StepHotspot {
            label: e.label.clone(),
            kind: e.kind.clone(),
            duration_ms: e.duration_ms,
            output_chars: e.output_chars,
        })
        .collect();
    by_output.sort_by(|a, b| b.output_chars.cmp(&a.output_chars));
    by_output.truncate(5);

    // Collect all subagent item_ids for parent matching
    let subagent_item_ids: Vec<Option<String>> = entries
        .iter()
        .filter(|e| e.kind == StepKind::SubagentTask)
        .map(|e| e.item_id.clone())
        .collect();

    let mut subagents: Vec<SubagentTraceSummary> = entries
        .iter()
        .filter(|e| e.kind == StepKind::SubagentTask)
        .map(|subagent| {
            let children: Vec<&StepTraceEntry> = entries
                .iter()
                .filter(|entry| {
                    entry.parent_item_id.is_some()
                        && entry.parent_item_id.as_deref() == subagent.item_id.as_deref()
                })
                .collect();
            let (input_tokens, output_tokens) = if usage_by_message.is_empty() {
                let input_tokens: u64 = children
                    .iter()
                    .filter(|e| e.kind == StepKind::TurnCompleted)
                    .map(|e| e.turn_input_tokens)
                    .sum();
                let output_tokens: u64 = children
                    .iter()
                    .filter(|e| e.kind == StepKind::TurnCompleted)
                    .map(|e| e.turn_output_tokens)
                    .sum();
                (input_tokens, output_tokens)
            } else {
                let input_tokens: u64 = usage_by_message
                    .values()
                    .filter(|u| u.parent_item_id.as_deref() == subagent.item_id.as_deref())
                    .map(|u| u.input_tokens)
                    .sum();
                let output_tokens: u64 = usage_by_message
                    .values()
                    .filter(|u| u.parent_item_id.as_deref() == subagent.item_id.as_deref())
                    .map(|u| u.output_tokens)
                    .sum();
                (input_tokens, output_tokens)
            };
            let total_tokens = input_tokens + output_tokens;
            SubagentTraceSummary {
                item_id: subagent.item_id.clone(),
                label: subagent.label.clone(),
                duration_ms: subagent.duration_ms,
                child_steps: children.len(),
                child_command_steps: children
                    .iter()
                    .filter(|e| e.kind == StepKind::CommandExecution)
                    .count(),
                child_mcp_steps: children
                    .iter()
                    .filter(|e| e.kind == StepKind::McpToolCall)
                    .count(),
                child_output_chars: children.iter().map(|e| e.output_chars).sum(),
                child_output_tokens_est: children.iter().map(|e| e.output_tokens_est).sum(),
                input_tokens,
                output_tokens,
                total_tokens,
                estimated_cost_usd: total_tokens as f64 * COST_PER_TOKEN_USD,
            }
        })
        .collect();
    subagents.sort_by(|a, b| {
        b.duration_ms
            .partial_cmp(&a.duration_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.child_steps.cmp(&a.child_steps))
    });

    // Token attribution: main agent = turn.completed with no parent or parent not a subagent
    let (main_agent_input_tokens, main_agent_output_tokens) = if usage_by_message.is_empty() {
        let main_agent_input_tokens: u64 = entries
            .iter()
            .filter(|e| {
                e.kind == StepKind::TurnCompleted
                    && !subagent_item_ids
                        .iter()
                        .any(|sid| sid.is_some() && sid.as_deref() == e.parent_item_id.as_deref())
            })
            .map(|e| e.turn_input_tokens)
            .sum();
        let main_agent_output_tokens: u64 = entries
            .iter()
            .filter(|e| {
                e.kind == StepKind::TurnCompleted
                    && !subagent_item_ids
                        .iter()
                        .any(|sid| sid.is_some() && sid.as_deref() == e.parent_item_id.as_deref())
            })
            .map(|e| e.turn_output_tokens)
            .sum();
        (main_agent_input_tokens, main_agent_output_tokens)
    } else {
        let main_agent_input_tokens: u64 = usage_by_message
            .values()
            .filter(|u| {
                !subagent_item_ids
                    .iter()
                    .any(|sid| sid.is_some() && sid.as_deref() == u.parent_item_id.as_deref())
            })
            .map(|u| u.input_tokens)
            .sum();
        let main_agent_output_tokens: u64 = usage_by_message
            .values()
            .filter(|u| {
                !subagent_item_ids
                    .iter()
                    .any(|sid| sid.is_some() && sid.as_deref() == u.parent_item_id.as_deref())
            })
            .map(|u| u.output_tokens)
            .sum();
        (main_agent_input_tokens, main_agent_output_tokens)
    };
    let main_agent_total_tokens = main_agent_input_tokens + main_agent_output_tokens;

    let subagent_total_input_tokens: u64 = subagents.iter().map(|s| s.input_tokens).sum();
    let subagent_total_output_tokens: u64 = subagents.iter().map(|s| s.output_tokens).sum();
    let subagent_total_tokens: u64 = subagents.iter().map(|s| s.total_tokens).sum();

    StepTraceSummary {
        total_steps: entries.len(),
        command_steps,
        mcp_steps,
        subagent_steps,
        agent_message_steps,
        failed_steps,
        total_output_chars,
        total_output_tokens_est,
        has_precise_timing,
        top_by_duration: by_duration,
        top_by_output: by_output,
        subagents,
        main_agent_input_tokens,
        main_agent_output_tokens,
        main_agent_total_tokens,
        main_agent_cost_usd: main_agent_total_tokens as f64 * COST_PER_TOKEN_USD,
        subagent_total_input_tokens,
        subagent_total_output_tokens,
        subagent_total_tokens,
        subagent_total_cost_usd: subagent_total_tokens as f64 * COST_PER_TOKEN_USD,
        unattributed_total_tokens: 0,
        unattributed_cost_usd: 0.0,
    }
}

fn message_usage_totals(v: &Value) -> (u64, u64) {
    let Some(usage) = v
        .get("message")
        .and_then(|m| m.get("usage"))
        .and_then(|u| u.as_object())
    else {
        return (0, 0);
    };

    let input_tokens = usage
        .get("input_tokens")
        .and_then(|n| n.as_u64())
        .unwrap_or(0)
        + usage
            .get("cache_creation_input_tokens")
            .and_then(|n| n.as_u64())
            .unwrap_or(0)
        + usage
            .get("cache_read_input_tokens")
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(|n| n.as_u64())
        .unwrap_or(0);
    (input_tokens, output_tokens)
}

fn estimate_tokens(chars: usize) -> u64 {
    chars.div_ceil(4) as u64
}

fn shorten(s: &str) -> String {
    let compact = s.replace('\n', " ");
    let trimmed = compact.trim();
    if trimmed.len() <= 120 {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..117])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(offset_ms: f64, line: &str) -> TimedLineEvent {
        TimedLineEvent {
            stream: "stdout".to_string(),
            offset_ms,
            line: line.to_string(),
        }
    }

    #[test]
    fn extract_step_trace_pairs_started_and_completed_commands() {
        let trace = extract_step_trace(&[
            event(10.0, r#"{"type":"item.started","item":{"id":"item_1","type":"command_execution","command":"kin overview --compact","status":"in_progress"}}"#),
            event(18.5, r#"{"type":"item.completed","item":{"id":"item_1","type":"command_execution","command":"kin overview --compact","aggregated_output":"hello","exit_code":0,"status":"completed"}}"#),
        ]);

        assert_eq!(trace.entries.len(), 1);
        let entry = &trace.entries[0];
        assert_eq!(entry.kind, StepKind::CommandExecution);
        assert_eq!(entry.label, "kin overview --compact");
        assert_eq!(entry.parent_item_id, None);
        assert_eq!(entry.output_chars, 5);
        assert_eq!(entry.duration_ms, Some(8.5));
        assert_eq!(trace.summary.command_steps, 1);
    }

    #[test]
    fn extract_step_trace_captures_mcp_and_failures() {
        let trace = extract_step_trace(&[
            event(1.0, r#"{"type":"item.started","item":{"id":"item_2","type":"mcp_tool_call","server":"kin","tool":"semantic_search","status":"in_progress"}}"#),
            event(3.0, r#"{"type":"item.completed","item":{"id":"item_2","type":"mcp_tool_call","server":"kin","tool":"semantic_search","result":{"content":[{"type":"text","text":"abc"}]},"status":"failed"}}"#),
        ]);

        assert_eq!(trace.summary.mcp_steps, 1);
        assert_eq!(trace.summary.failed_steps, 1);
        assert_eq!(trace.entries[0].label, "kin::semantic_search");
    }

    #[test]
    fn extract_step_trace_handles_claude_result_events() {
        let trace = extract_step_trace(&[event(
            42.0,
            r#"{"type":"result","subtype":"success","duration_ms":1234.0,"result":"done"}"#,
        )]);

        assert_eq!(trace.entries.len(), 1);
        assert_eq!(trace.entries[0].kind, StepKind::Result);
        assert_eq!(trace.entries[0].duration_ms, Some(1234.0));
        assert!(trace.summary.has_precise_timing);
    }

    #[test]
    fn extract_step_trace_pairs_claude_tool_use_and_result() {
        let trace = extract_step_trace(&[
            event(
                5.0,
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"tool_1","name":"Bash","input":{"command":"kin search save --show-body --limit 5"}}]}}"#,
            ),
            event(
                18.0,
                r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"tool_1","content":"Found 1 entity","is_error":false}]},"tool_use_result":{"stdout":"Found 1 entity","stderr":""}}"#,
            ),
        ]);

        assert_eq!(trace.entries.len(), 1);
        let entry = &trace.entries[0];
        assert_eq!(entry.kind, StepKind::CommandExecution);
        assert_eq!(entry.label, "kin search save --show-body --limit 5");
        assert_eq!(entry.status.as_deref(), Some("completed"));
        assert_eq!(entry.output_chars, "Found 1 entity".len());
        assert_eq!(entry.duration_ms, Some(13.0));
        assert_eq!(trace.summary.command_steps, 1);
    }

    #[test]
    fn extract_step_trace_records_claude_agent_messages() {
        let trace = extract_step_trace(&[event(
            7.0,
            r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"I should use kin first."},{"type":"text","text":"Done."}]}}"#,
        )]);

        assert_eq!(trace.entries.len(), 2);
        assert_eq!(trace.entries[0].kind, StepKind::AgentMessage);
        assert_eq!(trace.entries[1].kind, StepKind::AgentMessage);
        assert_eq!(trace.summary.agent_message_steps, 2);
    }

    #[test]
    fn extract_step_trace_records_claude_subagent_task() {
        let trace = extract_step_trace(&[
            event(
                10.0,
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"task_1","name":"Agent","input":{"subagent_type":"reviewer","description":"check auth module"}}]}}"#,
            ),
            event(
                42.0,
                r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"task_1","content":"review complete","is_error":false}]}}"#,
            ),
        ]);

        assert_eq!(trace.entries.len(), 1);
        assert_eq!(trace.entries[0].kind, StepKind::SubagentTask);
        assert_eq!(trace.entries[0].label, "Subagent reviewer: check auth module");
        assert_eq!(trace.summary.subagent_steps, 1);
        assert_eq!(trace.summary.subagents.len(), 1);
        assert_eq!(trace.summary.subagents[0].label, "Subagent reviewer: check auth module");
        assert_eq!(trace.summary.subagents[0].child_steps, 0);
    }

    #[test]
    fn extract_step_trace_preserves_parent_subagent_id_for_nested_tool_calls() {
        let trace = extract_step_trace(&[
            event(
                10.0,
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"agent_1","name":"Agent","input":{"subagent_type":"explore","description":"trace flow"}}]}}"#,
            ),
            event(
                12.0,
                r#"{"type":"assistant","parent_tool_use_id":"agent_1","message":{"content":[{"type":"tool_use","id":"tool_2","name":"Bash","input":{"command":"kin overview --compact"}}]}}"#,
            ),
            event(
                20.0,
                r#"{"type":"user","parent_tool_use_id":"agent_1","message":{"content":[{"type":"tool_result","tool_use_id":"tool_2","content":"ok","is_error":false}]}}"#,
            ),
        ]);

        assert_eq!(trace.entries.len(), 1);
        assert_eq!(trace.entries[0].kind, StepKind::CommandExecution);
        assert_eq!(trace.entries[0].parent_item_id.as_deref(), Some("agent_1"));
        assert_eq!(trace.entries[0].label, "kin overview --compact");
    }

    #[test]
    fn extract_step_trace_summarizes_nested_subagent_work() {
        let trace = extract_step_trace(&[
            event(
                10.0,
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"agent_1","name":"Agent","input":{"subagent_type":"explore","description":"trace flow"}}]}}"#,
            ),
            event(
                12.0,
                r#"{"type":"assistant","parent_tool_use_id":"agent_1","message":{"content":[{"type":"tool_use","id":"tool_2","name":"Bash","input":{"command":"kin overview --compact"}}]}}"#,
            ),
            event(
                20.0,
                r#"{"type":"user","parent_tool_use_id":"agent_1","message":{"content":[{"type":"tool_result","tool_use_id":"tool_2","content":"ok","is_error":false}]}}"#,
            ),
            event(
                30.0,
                r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"agent_1","content":"complete","is_error":false}]}}"#,
            ),
        ]);

        assert_eq!(trace.summary.subagent_steps, 1);
        assert_eq!(trace.summary.subagents.len(), 1);
        let subagent = &trace.summary.subagents[0];
        assert_eq!(subagent.label, "Subagent explore: trace flow");
        assert_eq!(subagent.child_steps, 1);
        assert_eq!(subagent.child_command_steps, 1);
        assert_eq!(subagent.child_mcp_steps, 0);
    }

    #[test]
    fn extract_step_trace_attributes_tokens_to_main_vs_subagent() {
        let trace = extract_step_trace(&[
            // Main agent turn.completed (no parent)
            event(
                5.0,
                r#"{"type":"turn.completed","usage":{"input_tokens":1000,"output_tokens":500}}"#,
            ),
            // Subagent spawned
            event(
                10.0,
                r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"agent_1","name":"Agent","input":{"subagent_type":"explore","description":"investigate auth"}}]}}"#,
            ),
            // Subagent turn.completed (parented to agent_1)
            event(
                15.0,
                r#"{"type":"turn.completed","parent_tool_use_id":"agent_1","usage":{"input_tokens":2000,"output_tokens":800}}"#,
            ),
            // Another subagent turn.completed
            event(
                20.0,
                r#"{"type":"turn.completed","parent_tool_use_id":"agent_1","usage":{"input_tokens":1500,"output_tokens":600}}"#,
            ),
            // Subagent completes
            event(
                25.0,
                r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"agent_1","content":"done","is_error":false}]}}"#,
            ),
            // Another main agent turn.completed
            event(
                30.0,
                r#"{"type":"turn.completed","usage":{"input_tokens":800,"output_tokens":300}}"#,
            ),
        ]);

        // Main agent: 1000+500 + 800+300 = 2600 total
        assert_eq!(trace.summary.main_agent_input_tokens, 1800);
        assert_eq!(trace.summary.main_agent_output_tokens, 800);
        assert_eq!(trace.summary.main_agent_total_tokens, 2600);

        // Subagent: 2000+800 + 1500+600 = 4900 total
        assert_eq!(trace.summary.subagent_total_input_tokens, 3500);
        assert_eq!(trace.summary.subagent_total_output_tokens, 1400);
        assert_eq!(trace.summary.subagent_total_tokens, 4900);

        // Per-subagent breakdown
        assert_eq!(trace.summary.subagents.len(), 1);
        let sub = &trace.summary.subagents[0];
        assert_eq!(sub.input_tokens, 3500);
        assert_eq!(sub.output_tokens, 1400);
        assert_eq!(sub.total_tokens, 4900);

        // Cost estimates (rough approximation)
        let main_cost = 2600.0 * COST_PER_TOKEN_USD;
        let sub_cost = 4900.0 * COST_PER_TOKEN_USD;
        assert!((trace.summary.main_agent_cost_usd - main_cost).abs() < 1e-10);
        assert!((trace.summary.subagent_total_cost_usd - sub_cost).abs() < 1e-10);
        assert!((sub.estimated_cost_usd - sub_cost).abs() < 1e-10);
    }

    #[test]
    fn extract_step_trace_turn_completed_stores_structured_tokens() {
        let trace = extract_step_trace(&[event(
            10.0,
            r#"{"type":"turn.completed","usage":{"input_tokens":4200,"output_tokens":1300}}"#,
        )]);

        assert_eq!(trace.entries.len(), 1);
        let entry = &trace.entries[0];
        assert_eq!(entry.kind, StepKind::TurnCompleted);
        assert_eq!(entry.turn_input_tokens, 4200);
        assert_eq!(entry.turn_output_tokens, 1300);
        assert!(entry.label.contains("4200"));
        assert!(entry.label.contains("1300"));
    }

    #[test]
    fn extract_step_trace_zero_tokens_when_no_usage() {
        let trace = extract_step_trace(&[event(
            10.0,
            r#"{"type":"turn.completed"}"#,
        )]);

        assert_eq!(trace.entries.len(), 1);
        assert_eq!(trace.entries[0].turn_input_tokens, 0);
        assert_eq!(trace.entries[0].turn_output_tokens, 0);
        assert_eq!(trace.summary.main_agent_total_tokens, 0);
    }

    #[test]
    fn extract_step_trace_attributes_claude_message_usage_and_dedupes_by_message_id() {
        let trace = extract_step_trace(&[
            // Same top-level Claude message emitted twice with the same id/usage.
            event(
                5.0,
                r#"{"type":"assistant","message":{"id":"msg_main_1","usage":{"input_tokens":3,"cache_creation_input_tokens":7087,"cache_read_input_tokens":8650,"output_tokens":10},"content":[{"type":"thinking","thinking":"..."},{"type":"tool_use","id":"agent_1","name":"Agent","input":{"subagent_type":"explore","description":"trace flow"}}]}}"#,
            ),
            event(
                6.0,
                r#"{"type":"assistant","message":{"id":"msg_main_1","usage":{"input_tokens":3,"cache_creation_input_tokens":7087,"cache_read_input_tokens":8650,"output_tokens":10},"content":[{"type":"tool_use","id":"agent_1","name":"Agent","input":{"subagent_type":"explore","description":"trace flow"}}]}}"#,
            ),
            // Subagent message usage should be attributed to the subagent via parent_tool_use_id.
            event(
                10.0,
                r#"{"type":"assistant","parent_tool_use_id":"agent_1","message":{"id":"msg_sub_1","usage":{"input_tokens":4,"cache_creation_input_tokens":100,"cache_read_input_tokens":200,"output_tokens":5},"content":[{"type":"tool_use","id":"tool_1","name":"Bash","input":{"command":"kin overview --compact"}}]}}"#,
            ),
            event(
                12.0,
                r#"{"type":"user","parent_tool_use_id":"agent_1","message":{"content":[{"type":"tool_result","tool_use_id":"tool_1","content":"ok","is_error":false}]}}"#,
            ),
            event(
                15.0,
                r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"agent_1","content":"done","is_error":false}]}}"#,
            ),
            // Final top-level answer message, also attributed to main agent.
            event(
                20.0,
                r#"{"type":"assistant","message":{"id":"msg_main_2","usage":{"input_tokens":1,"cache_creation_input_tokens":1202,"cache_read_input_tokens":15737,"output_tokens":1},"content":[{"type":"text","text":"final"}]}}"#,
            ),
        ]);

        // Main agent = msg_main_1 + msg_main_2, with msg_main_1 counted once.
        assert_eq!(trace.summary.main_agent_input_tokens, 3 + 7087 + 8650 + 1 + 1202 + 15737);
        assert_eq!(trace.summary.main_agent_output_tokens, 11);
        assert_eq!(
            trace.summary.main_agent_total_tokens,
            (3 + 7087 + 8650 + 1 + 1202 + 15737) + 11
        );

        // Subagent = msg_sub_1
        assert_eq!(trace.summary.subagent_total_input_tokens, 4 + 100 + 200);
        assert_eq!(trace.summary.subagent_total_output_tokens, 5);
        assert_eq!(trace.summary.subagent_total_tokens, 309);

        assert_eq!(trace.summary.subagents.len(), 1);
        let sub = &trace.summary.subagents[0];
        assert_eq!(sub.input_tokens, 304);
        assert_eq!(sub.output_tokens, 5);
        assert_eq!(sub.total_tokens, 309);
    }
}
