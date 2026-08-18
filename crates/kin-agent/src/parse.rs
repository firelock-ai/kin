// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Tool-call extraction from an OpenAI-compatible chat response.
//!
//! Three shapes are recognized. The structured `tool_calls` array every compliant
//! server emits, the Qwen text shape `<tool_call><function=name><parameter=k>v</parameter>`,
//! and the Gemma text shape `<|tool_call>call: name{args}<tool_call|>`. The two text
//! shapes are what local servers hand back when a model answers in prose instead of
//! filling the protocol field, and a loop that cannot read them stalls on every local
//! model that does it. The text-shape readers follow the ones proven in kin-bench's
//! `crates/kin-bench-engine/src/live/agent/openai_compat.rs`.

use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// One tool call the model asked for, already normalized across wire shapes.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
    pub shape: CallShape,
}

/// Which wire shape a call arrived in. Recorded so a transcript can show that a
/// model never used the protocol field, which is a model fact rather than a Kin fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallShape {
    Native,
    QwenText,
    GemmaText,
    JsonText,
}

impl CallShape {
    pub fn as_str(self) -> &'static str {
        match self {
            CallShape::Native => "native",
            CallShape::QwenText => "qwen_text",
            CallShape::GemmaText => "gemma_text",
            CallShape::JsonText => "json_text",
        }
    }
}

/// What a single model turn amounted to.
#[derive(Debug, Clone, PartialEq)]
pub enum Turn {
    /// The model answered without asking for a tool.
    Final { text: String },
    /// The model asked for one or more tools, with whatever prose came alongside.
    ToolCalls { text: String, calls: Vec<ToolCall> },
    /// Nothing usable came back. Carries why, for the repair turn's message.
    Unusable { reason: String, text: String },
}

/// A tool name safe to route: it cannot be a path, a flag, or a shell fragment.
pub fn is_safe_tool_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch == '-' || ch.is_ascii_alphanumeric())
}

/// Read one `choices[0]` object into a turn.
///
/// `known` is the belt: every name the router will accept. Text-shaped calls are only
/// recognized for names in the belt, because the text shapes are ambiguous enough that
/// an unconstrained reader would mint calls out of prose that merely discusses a tool.
pub fn parse_choice(choice: &Value, known: &BTreeSet<String>) -> Turn {
    let message = choice.get("message").unwrap_or(&Value::Null);
    let text = message
        .get("content")
        .and_then(content_to_text)
        .unwrap_or_default();

    let native = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(|calls| parse_native_tool_calls(calls))
        .unwrap_or_default();
    if !native.is_empty() {
        return Turn::ToolCalls {
            text,
            calls: native,
        };
    }

    for (parser, shape) in [
        (
            parse_qwen_text_calls as fn(&str, &BTreeSet<String>) -> Vec<ToolCall>,
            CallShape::QwenText,
        ),
        (parse_gemma_text_calls, CallShape::GemmaText),
        (parse_json_text_calls, CallShape::JsonText),
    ] {
        let calls = parser(&text, known);
        if !calls.is_empty() {
            let _ = shape;
            return Turn::ToolCalls {
                text: strip_tool_call_markup(&text),
                calls,
            };
        }
    }

    let finish = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .unwrap_or("");
    if text.trim().is_empty() {
        return Turn::Unusable {
            reason: format!(
                "the response carried no content and no tool_calls (finish_reason: {})",
                if finish.is_empty() { "absent" } else { finish }
            ),
            text,
        };
    }
    if finish == "length" {
        return Turn::Unusable {
            reason: "the response was cut off by the output token limit before it finished"
                .to_string(),
            text,
        };
    }
    if finish == "tool_calls" {
        return Turn::Unusable {
            reason: "finish_reason was tool_calls but no readable tool call was present"
                .to_string(),
            text,
        };
    }
    Turn::Final { text }
}

/// Flatten a `content` field, which is a string on most servers and a block array on some.
fn content_to_text(content: &Value) -> Option<String> {
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(blocks) => {
            let mut out = String::new();
            for block in blocks {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    out.push_str(text);
                }
            }
            Some(out)
        }
        Value::Null => None,
        _ => None,
    }
}

fn parse_native_tool_calls(calls: &[Value]) -> Vec<ToolCall> {
    let mut out = Vec::new();
    for (index, call) in calls.iter().enumerate() {
        let function = call.get("function").unwrap_or(&Value::Null);
        let Some(name) = function.get("name").and_then(Value::as_str) else {
            continue;
        };
        let arguments = match function.get("arguments") {
            // Servers send arguments as a JSON string; a few send the object directly.
            Some(Value::String(raw)) => parse_arguments_string(raw),
            Some(Value::Object(map)) => Value::Object(map.clone()),
            _ => Value::Object(Map::new()),
        };
        out.push(ToolCall {
            id: call
                .get("id")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("native_call_{index}")),
            name: name.to_string(),
            arguments,
            shape: CallShape::Native,
        });
    }
    out
}

/// An arguments string that is not valid JSON becomes an explicit marker rather than an
/// empty object, so schema validation reports a malformed call instead of a call with no
/// arguments. Those are different failures and the repair turn says different things.
fn parse_arguments_string(raw: &str) -> Value {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Value::Object(Map::new());
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value @ Value::Object(_)) => value,
        Ok(other) => {
            let mut map = Map::new();
            map.insert("__kin_agent_non_object_arguments".into(), other);
            Value::Object(map)
        }
        Err(err) => {
            let mut map = Map::new();
            map.insert(
                "__kin_agent_unparsed_arguments".into(),
                Value::String(trimmed.to_string()),
            );
            map.insert(
                "__kin_agent_parse_error".into(),
                Value::String(err.to_string()),
            );
            Value::Object(map)
        }
    }
}

/// True when arguments could not be read off the wire at all.
pub fn arguments_are_malformed(arguments: &Value) -> Option<String> {
    let object = arguments.as_object()?;
    if let Some(raw) = object.get("__kin_agent_unparsed_arguments") {
        let err = object
            .get("__kin_agent_parse_error")
            .and_then(Value::as_str)
            .unwrap_or("not valid JSON");
        return Some(format!(
            "the arguments were not valid JSON ({}): {}",
            err,
            raw.as_str().unwrap_or_default()
        ));
    }
    if object.contains_key("__kin_agent_non_object_arguments") {
        return Some("the arguments were valid JSON but not a JSON object".to_string());
    }
    None
}

/// Qwen: `<tool_call><function=name><parameter=key>value</parameter></function></tool_call>`
fn parse_qwen_text_calls(text: &str, known: &BTreeSet<String>) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    let mut offset = 0;
    while let Some(start_rel) = text[offset..].find("<tool_call>") {
        let body_start = offset + start_rel + "<tool_call>".len();
        let Some(end_rel) = text[body_start..].find("</tool_call>") else {
            break;
        };
        let body_end = body_start + end_rel;
        if let Some(call) = parse_qwen_block(&text[body_start..body_end], known, calls.len()) {
            calls.push(call);
        }
        offset = body_end + "</tool_call>".len();
    }
    calls
}

fn parse_qwen_block(block: &str, known: &BTreeSet<String>, index: usize) -> Option<ToolCall> {
    let function_start = block.find("<function=")? + "<function=".len();
    let rest = &block[function_start..];
    let name_end = rest.find('>')?;
    let mut name = rest[..name_end].trim();
    // Some templates qualify the name, as in `functions.semantic_locate`.
    if let Some(dot) = name.rfind('.') {
        name = &name[dot + 1..];
    }
    if !known.contains(name) || !is_safe_tool_name(name) {
        return None;
    }
    let body_start = function_start + name_end + 1;
    let body_end = block[body_start..]
        .find("</function>")
        .map(|end| body_start + end)
        .unwrap_or(block.len());
    Some(ToolCall {
        id: format!("qwen_text_call_{index}"),
        name: name.to_string(),
        arguments: Value::Object(parse_qwen_parameters(&block[body_start..body_end])),
        shape: CallShape::QwenText,
    })
}

fn parse_qwen_parameters(text: &str) -> Map<String, Value> {
    let mut args = Map::new();
    let mut offset = 0;
    while let Some(start_rel) = text[offset..].find("<parameter=") {
        let name_start = offset + start_rel + "<parameter=".len();
        let rest = &text[name_start..];
        let Some(name_end_rel) = rest.find('>') else {
            break;
        };
        let name = rest[..name_end_rel].trim().to_string();
        let value_start = name_start + name_end_rel + 1;
        let Some(value_end_rel) = text[value_start..].find("</parameter>") else {
            break;
        };
        let value_end = value_start + value_end_rel;
        let raw = text[value_start..value_end].trim();
        args.insert(name, scalar_from_text(raw));
        offset = value_end + "</parameter>".len();
    }
    args
}

/// Gemma: `<|tool_call>call: name{"k": "v"}<tool_call|>`
fn parse_gemma_text_calls(text: &str, known: &BTreeSet<String>) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    let mut offset = 0;
    while let Some(start_rel) = text[offset..].find("<|tool_call>") {
        let body_start = offset + start_rel + "<|tool_call>".len();
        let close = text[body_start..]
            .find("<tool_call|>")
            .or_else(|| text[body_start..].find("<|tool_call|>"));
        let body_end = body_start + close.unwrap_or(text.len() - body_start);
        if let Some(call) = parse_gemma_block(&text[body_start..body_end], known, calls.len()) {
            calls.push(call);
        }
        let Some(_) = close else { break };
        offset = body_end
            + if text[body_end..].starts_with("<tool_call|>") {
                "<tool_call|>".len()
            } else {
                "<|tool_call|>".len()
            };
        if offset >= text.len() {
            break;
        }
    }
    calls
}

fn parse_gemma_block(block: &str, known: &BTreeSet<String>, index: usize) -> Option<ToolCall> {
    let block = block.trim();
    let call_start = block.find("call:")?;
    let rest = &block[call_start + "call:".len()..];
    let brace_start = rest.find('{')?;
    let mut name = rest[..brace_start].trim();
    if let Some(dot) = name.rfind('.') {
        name = &name[dot + 1..];
    }
    if !known.contains(name) || !is_safe_tool_name(name) {
        return None;
    }
    let args_str = &rest[brace_start..];
    let brace_end = args_str.rfind('}')?;
    // Gemma escapes quotes with its own special tokens rather than backslashes.
    let body = args_str[1..brace_end]
        .replace("<|\"|>", "\"")
        .replace("<|\\\"|>", "\"")
        .replace("<|'|>", "'")
        .replace("<|\\'|>", "'");
    Some(ToolCall {
        id: format!("gemma_text_call_{index}"),
        name: name.to_string(),
        arguments: Value::Object(parse_gemma_arguments(&body)),
        shape: CallShape::GemmaText,
    })
}

/// Gemma's argument body is usually valid JSON once the quote tokens are normalized.
/// When it is not, fall back to reading `key: value` pairs at the top level.
fn parse_gemma_arguments(body: &str) -> Map<String, Value> {
    let wrapped = format!("{{{body}}}");
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&wrapped) {
        return map;
    }
    let mut args = Map::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut current = String::new();
    let mut fields = Vec::new();
    for ch in body.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => {
                current.push(ch);
                escaped = true;
            }
            '"' => {
                in_string = !in_string;
                current.push(ch);
            }
            '{' | '[' if !in_string => {
                depth += 1;
                current.push(ch);
            }
            '}' | ']' if !in_string => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if !in_string && depth == 0 => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        fields.push(current);
    }
    for field in fields {
        let Some(colon) = split_top_level_colon(&field) else {
            continue;
        };
        let key = field[..colon].trim().trim_matches('"').to_string();
        if key.is_empty() {
            continue;
        }
        args.insert(key, scalar_from_text(field[colon + 1..].trim()));
    }
    args
}

fn split_top_level_colon(field: &str) -> Option<usize> {
    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in field.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' | '[' if !in_string => depth += 1,
            '}' | ']' if !in_string => depth = depth.saturating_sub(1),
            ':' if !in_string && depth == 0 => return Some(idx),
            _ => {}
        }
    }
    None
}

/// Read a bare text value into the JSON scalar it obviously is, string otherwise.
fn scalar_from_text(raw: &str) -> Value {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            return value;
        }
    }
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        if let Ok(Value::String(s)) = serde_json::from_str::<Value>(trimmed) {
            return Value::String(s);
        }
    }
    match trimmed {
        "true" => return Value::Bool(true),
        "false" => return Value::Bool(false),
        "null" => return Value::Null,
        _ => {}
    }
    if let Ok(int) = trimmed.parse::<i64>() {
        return Value::from(int);
    }
    if let Ok(float) = trimmed.parse::<f64>() {
        if float.is_finite() {
            return Value::from(float);
        }
    }
    Value::String(trimmed.to_string())
}

/// The plain shape: `<tool_call>{"name": "x", "arguments": {...}}</tool_call>`, which is
/// what several LM Studio templates emit under a tool_choice constraint.
fn parse_json_text_calls(text: &str, known: &BTreeSet<String>) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    let mut offset = 0;
    while let Some(start_rel) = text[offset..].find("<tool_call>") {
        let body_start = offset + start_rel + "<tool_call>".len();
        let (body_end, next) = match text[body_start..].find("</tool_call>") {
            Some(end) => (body_start + end, body_start + end + "</tool_call>".len()),
            None => (text.len(), text.len()),
        };
        let body = text[body_start..body_end].trim();
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(body) {
            let name = map
                .get("name")
                .or_else(|| map.get("tool"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let mut name = name;
            if let Some(dot) = name.rfind('.') {
                name = &name[dot + 1..];
            }
            if known.contains(name) && is_safe_tool_name(name) {
                let arguments = map
                    .get("arguments")
                    .or_else(|| map.get("parameters"))
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new()));
                let arguments = match arguments {
                    Value::String(raw) => parse_arguments_string(&raw),
                    other @ Value::Object(_) => other,
                    _ => Value::Object(Map::new()),
                };
                let index = calls.len();
                calls.push(ToolCall {
                    id: format!("json_text_call_{index}"),
                    name: name.to_string(),
                    arguments,
                    shape: CallShape::JsonText,
                });
            }
        }
        if next >= text.len() {
            break;
        }
        offset = next;
    }
    calls
}

/// Remove the tool-call markup from prose so the transcript's text block reads as text.
fn strip_tool_call_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let qwen = rest.find("<tool_call>");
        let gemma = rest.find("<|tool_call>");
        let (start, open, close) = match (qwen, gemma) {
            (Some(q), Some(g)) if q <= g => (q, "<tool_call>", "</tool_call>"),
            (Some(_), Some(g)) => (g, "<|tool_call>", "<tool_call|>"),
            (Some(q), None) => (q, "<tool_call>", "</tool_call>"),
            (None, Some(g)) => (g, "<|tool_call>", "<tool_call|>"),
            (None, None) => {
                out.push_str(rest);
                break;
            }
        };
        out.push_str(&rest[..start]);
        let after_open = start + open.len();
        match rest[after_open..].find(close) {
            Some(end) => rest = &rest[after_open + end + close.len()..],
            None => break,
        }
    }
    out.trim().to_string()
}
