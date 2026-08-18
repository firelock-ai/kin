// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Transcript writers.
//!
//! Two files. `transcript.jsonl` is the Claude Code stream-json shape, because that is
//! what the fleet's analyzers already read, and emitting anything else would mean writing
//! new analyzers to measure a run. Every record carries a timestamp, because per-call
//! latency is derived by subtracting a `tool_use` stamp from its matching `tool_result`
//! and a record without one silently drops out of the timing.
//!
//! `kin-trace.jsonl` is the sidecar, one row per tool call, joinable on `tool_use_id`.
//! Everything Kin-specific lives there rather than in the stream, so a strict reader of
//! the stream never chokes and the existing analyzers keep working untouched.

use serde_json::{json, Map, Value};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// An RFC3339 UTC timestamp with milliseconds, the shape the analyzers parse.
pub fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

pub struct TranscriptWriter {
    stream: BufWriter<File>,
    trace: BufWriter<File>,
    session_id: String,
}

impl TranscriptWriter {
    pub fn create(out_dir: &Path, session_id: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(out_dir)?;
        Ok(TranscriptWriter {
            stream: BufWriter::new(File::create(out_dir.join("transcript.jsonl"))?),
            trace: BufWriter::new(File::create(out_dir.join("kin-trace.jsonl"))?),
            session_id: session_id.to_string(),
        })
    }

    fn write_stream(&mut self, mut record: Value) -> std::io::Result<()> {
        if let Some(object) = record.as_object_mut() {
            object.insert("session_id".into(), Value::String(self.session_id.clone()));
            object.entry("timestamp").or_insert_with(|| Value::String(now_iso()));
        }
        writeln!(self.stream, "{record}")?;
        self.stream.flush()
    }

    /// The init record. `mcp_server_errors` is non-empty exactly when Kin never attached,
    /// which is the one condition under which a run must not be scored as a Kin run.
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        &mut self,
        model: &str,
        cwd: &Path,
        tools: &[String],
        mcp_status: &str,
        mcp_errors: &[String],
        agent_meta: Value,
    ) -> std::io::Result<()> {
        self.write_stream(json!({
            "type": "system",
            "subtype": "init",
            "model": model,
            "cwd": cwd.display().to_string(),
            "permissionMode": "kin-agent",
            "tools": tools,
            "mcp_servers": [{ "name": "kin", "status": mcp_status }],
            "mcp_server_errors": mcp_errors,
            "kin_agent": agent_meta,
        }))
    }

    /// One model turn: its prose and the tool calls it asked for.
    pub fn assistant(
        &mut self,
        model: &str,
        message_id: &str,
        text: &str,
        tool_uses: &[(String, String, Value)],
        usage: Option<Value>,
    ) -> std::io::Result<()> {
        let mut content = Vec::new();
        if !text.trim().is_empty() {
            content.push(json!({ "type": "text", "text": text }));
        }
        for (id, name, input) in tool_uses {
            content.push(json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": input,
            }));
        }
        let mut message = Map::new();
        message.insert("id".into(), Value::String(message_id.to_string()));
        message.insert("type".into(), Value::String("message".into()));
        message.insert("role".into(), Value::String("assistant".into()));
        message.insert("model".into(), Value::String(model.to_string()));
        message.insert("content".into(), Value::Array(content));
        // Usage is written only when the endpoint reported it. An absent count stays
        // absent rather than becoming a zero that reads like a measured value.
        if let Some(usage) = usage {
            message.insert("usage".into(), usage);
        }
        self.write_stream(json!({ "type": "assistant", "message": Value::Object(message) }))
    }

    /// One observation, written immediately after the call it answers.
    pub fn tool_result(
        &mut self,
        tool_use_id: &str,
        content: &str,
        is_error: bool,
    ) -> std::io::Result<()> {
        self.write_stream(json!({
            "type": "user",
            "message": {
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": content,
                    "is_error": is_error,
                }]
            }
        }))
    }

    /// The terminal record. Written on every exit path, including the failures, so a run
    /// that died is still measurable rather than a truncated file.
    #[allow(clippy::too_many_arguments)]
    pub fn result(
        &mut self,
        subtype: &str,
        is_error: bool,
        num_turns: u32,
        duration_ms: u128,
        duration_api_ms: u128,
        final_text: &str,
        usage: Option<Value>,
        kin_agent: Value,
    ) -> std::io::Result<Value> {
        let mut record = json!({
            "type": "result",
            "subtype": subtype,
            "is_error": is_error,
            "num_turns": num_turns,
            "duration_ms": duration_ms as u64,
            "duration_api_ms": duration_api_ms as u64,
            "result": final_text,
            "total_cost_usd": Value::Null,
            "kin_agent": kin_agent,
            "session_id": self.session_id.clone(),
            "timestamp": now_iso(),
        });
        if let Some(usage) = usage {
            record["usage"] = usage;
        }
        writeln!(self.stream, "{record}")?;
        self.stream.flush()?;
        Ok(record)
    }

    /// One sidecar row.
    pub fn trace(&mut self, mut row: Value) -> std::io::Result<()> {
        if let Some(object) = row.as_object_mut() {
            object.entry("ts").or_insert_with(|| Value::String(now_iso()));
            object.insert("session_id".into(), Value::String(self.session_id.clone()));
        }
        writeln!(self.trace, "{row}")?;
        self.trace.flush()
    }
}
