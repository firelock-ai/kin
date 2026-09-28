// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Lossless, byte-bounded pages of a frozen semantic trace.
//!
//! Ordinary hops remain ordinary `chain` rows. Only a semantic record larger
//! than a page is fragmented; its address and absolute hop identity accompany
//! every UTF-8 fragment. Neither source bodies nor safety readings are dropped.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const MAX_CURSOR_BYTES: usize = 256;
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 16;
const SNAPSHOT_TTL: Duration = Duration::from_secs(600);

/// Transport-owned presentation scope, attached before freezing a page so a
/// client-folder warning is measured with the answer and cannot change on resume.
pub const CLIENT_ROOT_ARGUMENT: &str = "__kin_client_root";

/// The same frozen-record transport serves traces and reference answers.
/// Records keep their original collection address, including nested samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageKind {
    Trace,
    References,
}

impl PageKind {
    fn primary(self) -> &'static str {
        match self {
            Self::Trace => "chain",
            Self::References => "references",
        }
    }

    fn tool(self) -> &'static str {
        match self {
            Self::Trace => "trace_data_flow",
            Self::References => "find_references",
        }
    }

    fn collections(self) -> &'static [&'static str] {
        match self {
            Self::Trace => &["chain", "candidates", "more_candidates"],
            Self::References => &[
                "references",
                "candidates",
                "interface_dispatch.candidates",
                "call_sites.candidates",
                "candidates_by_owner",
            ],
        }
    }
}

/// Caller-owned authority identity and the normalized semantic query. The
/// authority stamp must change when the selected graph, its truth revision,
/// repository or authorization/session scope changes.
#[derive(Debug, Clone)]
pub struct Context {
    query: String,
    authority: String,
}

impl Context {
    /// Normalize traversal semantics identically on CLI and MCP. Byte budgets
    /// may change while paging; the question itself may not.
    pub fn from_arguments(
        arguments: &std::collections::HashMap<String, Value>,
        authority: &Value,
    ) -> Self {
        let integer = |key: &str, default: u64, maximum: u64| {
            arguments
                .get(key)
                .and_then(Value::as_u64)
                .unwrap_or(default)
                .clamp(1, maximum)
        };
        let text = |key: &str| arguments.get(key).and_then(Value::as_str).map(str::trim);
        let raw_direction = text("direction").unwrap_or("both").to_ascii_lowercase();
        let direction = match raw_direction.as_str() {
            "calls" | "callee" | "callees" | "out" | "outgoing" => "calls",
            "callers" | "caller" | "in" | "incoming" => "callers",
            "both" | "all" | "" => "both",
            other => other,
        };
        Self::new(
            &json!({
                "focal": text("focal"), "target": text("target"),
                "question": crate::outside_graph::question_argument(arguments),
                "direction": direction, "depth": integer("depth", 3, 8),
                "limit_per_step": integer("limit_per_step", crate::remediation::TRACE_DEFAULT_LIMIT_PER_STEP as u64, 25),
                "include_body": arguments.get("include_body").and_then(Value::as_bool)
                    .unwrap_or_else(|| !arguments.get("compact").and_then(Value::as_bool).unwrap_or(false)),
                "include_type_edges": arguments.get("include_type_edges").and_then(Value::as_bool).unwrap_or(false),
                "client_root": arguments.get(CLIENT_ROOT_ARGUMENT).and_then(Value::as_str),
            }),
            authority,
        )
    }

    pub fn new(query: &Value, authority: &Value) -> Self {
        Self {
            query: kin_blobs::digest(&serde_json::to_vec(query).expect("JSON query")).to_string(),
            authority: kin_blobs::digest(&serde_json::to_vec(authority).expect("JSON authority"))
                .to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    v: u8,
    snapshot: uuid::Uuid,
    record: usize,
    field: usize,
    byte: usize,
}

impl Cursor {
    fn encode(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(self).expect("cursor JSON"))
    }

    fn decode(token: &str) -> Result<Self, String> {
        if token.len() > MAX_CURSOR_BYTES {
            return Err("trace cursor is too long; restart without cursor".into());
        }
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| "invalid trace cursor; restart without cursor")?;
        let cursor: Self = serde_json::from_slice(&decoded)
            .map_err(|_| "invalid trace cursor; restart without cursor")?;
        if cursor.v != 1 {
            return Err("unsupported trace cursor version; restart without cursor".into());
        }
        Ok(cursor)
    }
}

/// Check the bounded wire syntax without accessing a trace snapshot or graph.
/// Acceptance here does not establish that the cursor is held or fresh; resume
/// must still validate its query, authority, and semantic record offsets.
pub fn validate_cursor_syntax(token: &str) -> Result<(), String> {
    Cursor::decode(token).map(|_| ())
}

#[derive(Debug)]
struct Record {
    collection: &'static str,
    index: usize,
    key: Option<String>,
    value: Value,
}

impl Record {
    fn identity(&self) -> Value {
        let mut address = json!({"collection": self.collection, "index": self.index});
        if let Some(key) = &self.key {
            address["key"] = json!(key);
        }
        if let Some(id) = self.value.get("entity_id").or_else(|| self.value.get("id")) {
            address["entity_id"] = id.clone();
            if matches!(self.key.as_deref(), Some("focal" | "focal_entity")) {
                address["step"] = json!(0);
                address["parent_step"] = json!(0);
            }
        }
        if let Some(caller) = self.value.get("caller").filter(|value| value.is_string()) {
            address["caller"] = caller.clone();
        }
        for key in ["step", "parent_step"] {
            if let Some(value) = self.value.get(key) {
                address[key] = value.clone();
            }
        }
        address
    }

    fn append_to(&self, page: &mut Value) {
        match self.collection {
            "readings" => {
                if !page["readings"].is_array() {
                    page["readings"] = json!([]);
                }
                page["readings"].as_array_mut().unwrap().push(json!({
                    "key": self.key, "value": self.value,
                }));
            }
            collection => {
                let mut slot = page;
                for key in collection.split('.') {
                    slot = &mut slot[key];
                }
                if !slot.is_array() {
                    *slot = json!([]);
                }
                slot.as_array_mut().unwrap().push(self.value.clone());
            }
        }
    }
}

struct Snapshot {
    kind: PageKind,
    id: uuid::Uuid,
    context: Context,
    created: Instant,
    bytes: usize,
    records: Vec<Record>,
    total_steps: usize,
    total_candidates: usize,
    original_verdict: Value,
    // Keep the captured answer's identity on every page, including pages
    // carrying only fragments. The complete safety reading is still paged
    // losslessly; a later transport must not borrow a newer graph observation.
    identity: serde_json::Map<String, Value>,
}

#[derive(Default)]
struct Cache {
    snapshots: VecDeque<Snapshot>,
    bytes: usize,
}

impl Cache {
    fn expire(&mut self, now: Instant) {
        while self
            .snapshots
            .front()
            .is_some_and(|snapshot| now.saturating_duration_since(snapshot.created) >= SNAPSHOT_TTL)
        {
            self.remove_oldest();
        }
    }

    fn remove_oldest(&mut self) {
        if let Some(snapshot) = self.snapshots.pop_front() {
            self.bytes = self.bytes.saturating_sub(snapshot.bytes);
        }
    }

    fn insert(&mut self, snapshot: Snapshot) {
        self.expire(Instant::now());
        while self.snapshots.len() >= MAX_CACHE_ENTRIES
            || self.bytes.saturating_add(snapshot.bytes) > MAX_CACHE_BYTES
        {
            self.remove_oldest();
        }
        self.bytes += snapshot.bytes;
        self.snapshots.push_back(snapshot);
    }
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cache::default()))
}

fn resident_bytes(value: &Value) -> usize {
    let heap = match value {
        Value::String(text) => text.capacity(),
        Value::Array(items) => items
            .capacity()
            .saturating_mul(std::mem::size_of::<Value>())
            .saturating_add(
                items
                    .iter()
                    .map(|item| resident_bytes(item).saturating_sub(std::mem::size_of::<Value>()))
                    .sum::<usize>(),
            ),
        Value::Object(fields) => fields
            .iter()
            .map(|(key, value)| {
                key.capacity()
                    .saturating_add(resident_bytes(value))
                    .saturating_add(128)
            })
            .sum(),
        _ => 0,
    };
    std::mem::size_of::<Value>().saturating_add(heap)
}

fn bytes(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |encoded| encoded.len())
}

/// Whether a response already carries the complete page envelope. Later
/// transports must preserve it, rather than append another unbudgeted reading.
pub fn is_page(payload: &Value) -> bool {
    payload
        .pointer("/_kin/page/version")
        .and_then(Value::as_u64)
        == Some(1)
}

/// Resume without repeating graph traversal. The concrete dispatcher samples
/// the current authority before calling this, so an old page cannot silently
/// span a graph write or a different selected graph.
pub fn resume(token: &str, context: &Context, max_bytes: usize) -> Result<Value, String> {
    let cursor = Cursor::decode(token)?;
    let mut cache = cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.expire(Instant::now());
    let snapshot = cache
        .snapshots
        .iter()
        .find(|snapshot| snapshot.id == cursor.snapshot)
        .ok_or("trace continuation expired or was evicted; restart without cursor")?;
    if snapshot.context.query != context.query {
        return Err("trace cursor query changed; restart without cursor".into());
    }
    if snapshot.context.authority != context.authority {
        return Err("trace cursor graph or authority scope changed; restart without cursor".into());
    }
    snapshot.page(cursor, max_bytes)
}

/// Attach the complete trust reading before selecting a response page. The
/// unbounded intermediate is never emitted and the old lossy ladder never
/// discards an entity body or hop from it.
pub fn finalize(
    result: crate::ToolCallResult,
    envelope: crate::Envelope,
    context: Context,
    max_bytes: usize,
) -> crate::ToolCallResult {
    finalize_kind(result, envelope, context, max_bytes, PageKind::Trace, false)
}

pub(crate) fn finalize_kind(
    result: crate::ToolCallResult,
    envelope: crate::Envelope,
    context: Context,
    max_bytes: usize,
    kind: PageKind,
    answer_only: bool,
) -> crate::ToolCallResult {
    let full_budget = crate::budget::ResponseBudget {
        max_chars: usize::MAX,
        envelope_reserve: 0,
        compact: false,
        answer_only,
        ..Default::default()
    };
    let full = crate::envelope::finalize_bounded(result, envelope, kind.tool(), &full_budget);
    let is_error = full.is_error;
    let Some(crate::ContentBlock::Text { text }) = full.content.first() else {
        return crate::ToolCallResult::error("trace response contains no semantic payload");
    };
    let outcome = serde_json::from_str::<Value>(text)
        .map_err(|error| error.to_string())
        .and_then(|mut payload| {
            // This intermediate never shipped. Its intentionally unlimited
            // accounting is not an observation about any emitted page.
            if let Some(envelope) = payload.get_mut("_kin").and_then(Value::as_object_mut) {
                envelope.remove("response");
            }
            start_kind(payload, context, max_bytes, kind)
        });
    match outcome {
        Ok(page) => crate::ToolCallResult {
            content: vec![crate::ContentBlock::Text {
                text: serde_json::to_string(&page).expect("trace page JSON"),
            }],
            is_error,
        },
        Err(error) => crate::ToolCallResult::error(error),
    }
}

/// Page the fully annotated result. The full payload is consumed, so the cache
/// stores one copy of each semantic record. Size is checked before admission.
pub fn start(payload: Value, context: Context, max_bytes: usize) -> Result<Value, String> {
    start_kind(payload, context, max_bytes, PageKind::Trace)
}

pub(crate) fn start_kind(
    mut payload: Value,
    context: Context,
    max_bytes: usize,
    kind: PageKind,
) -> Result<Value, String> {
    let total_steps = payload[kind.primary()].as_array().map_or(0, Vec::len);
    let mut complete = payload.clone();
    complete["next_cursor"] = Value::Null;
    complete["_kin"]["page"] = json!({
        "version": 1, "complete": true, "has_more": false,
        "total_steps": total_steps, "returned_steps": total_steps,
    });
    if kind == PageKind::References {
        complete["_kin"]["page"] = json!({
            "version": 1, "kind": "references", "complete": true, "has_more": false,
            "total_references": total_steps, "returned_references": total_steps,
        });
    }
    set_wire_size(&mut complete, max_bytes);
    if bytes(&complete) <= max_bytes {
        return Ok(complete);
    }
    let size = bytes(&payload).max(resident_bytes(&payload));
    if size > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "{} exceeds the {MAX_SNAPSHOT_BYTES}-byte continuation snapshot limit; narrow the query", kind.tool()
        ));
    }
    let original_verdict = payload
        .pointer("/_kin/verdict/state")
        .cloned()
        .unwrap_or(Value::Null);
    let identity: serde_json::Map<_, _> = ["repository", "graph_as_of", "answered_by", "runtime"]
        .into_iter()
        .filter_map(|key| {
            payload
                .get("_kin")?
                .get(key)
                .map(|value| (key.to_owned(), value.clone()))
        })
        .collect();
    let mut records = Vec::new();
    let mut total_candidates = 0;
    let fields = payload
        .as_object_mut()
        .ok_or("trace result is not an object")?;
    for &collection in kind.collections() {
        let present = if let Some((parent, key)) = collection.split_once('.') {
            fields.get(parent).and_then(|value| value.get(key))
        } else {
            fields.get(collection)
        };
        // Empty and non-array fields remain among the complete readings.
        // Removing them without creating records would lose their identity.
        if present.is_none_or(|value| value.as_array().is_none_or(|rows| rows.is_empty())) {
            continue;
        }
        let value = if let Some((parent, key)) = collection.split_once('.') {
            fields
                .get_mut(parent)
                .and_then(Value::as_object_mut)
                .and_then(|nested| nested.remove(key))
        } else {
            fields.remove(collection)
        };
        if let Some(Value::Array(rows)) = value {
            for (index, value) in rows.into_iter().enumerate() {
                let served_collection = collection;
                if served_collection != kind.primary() {
                    total_candidates += 1;
                }
                records.push(Record {
                    collection: served_collection,
                    index,
                    key: None,
                    value,
                });
            }
        }
    }
    if let Some(target) = fields
        .get_mut("target_ambiguity")
        .and_then(Value::as_object_mut)
        .filter(|target| {
            target
                .get("candidates")
                .and_then(Value::as_array)
                .is_some_and(|rows| !rows.is_empty())
        })
    {
        if let Some(Value::Array(rows)) = target.remove("candidates") {
            for (index, value) in rows.into_iter().enumerate() {
                total_candidates += 1;
                records.push(Record {
                    collection: "target_candidates",
                    index,
                    key: None,
                    value,
                });
            }
        }
    }
    for (index, (key, value)) in std::mem::take(fields).into_iter().enumerate() {
        records.push(Record {
            collection: "readings",
            index,
            key: Some(key),
            value,
        });
    }
    let retained_size = size
        .saturating_add(
            records
                .capacity()
                .saturating_mul(std::mem::size_of::<Record>()),
        )
        .saturating_add(
            records
                .iter()
                .filter_map(|record| record.key.as_ref())
                .map(String::capacity)
                .sum::<usize>(),
        )
        .saturating_add(std::mem::size_of::<Snapshot>() + 512)
        .saturating_add(resident_bytes(&Value::Object(identity.clone())));
    if retained_size > MAX_SNAPSHOT_BYTES {
        return Err(format!("{} exceeds the {MAX_SNAPSHOT_BYTES}-byte continuation snapshot limit; narrow the query", kind.tool()));
    }
    let snapshot = Snapshot {
        kind,
        id: uuid::Uuid::new_v4(),
        context,
        created: Instant::now(),
        bytes: retained_size,
        records,
        total_steps,
        total_candidates,
        original_verdict,
        identity,
    };
    let cursor = Cursor {
        v: 1,
        snapshot: snapshot.id,
        record: 0,
        field: 0,
        byte: 0,
    };
    let page = snapshot.page(cursor, max_bytes)?;
    cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(snapshot);
    Ok(page)
}

/// The single clause a partial trace page names as its limiting factor.
///
/// Readers split a verdict's limiting factor on the clause separator, so the
/// clause must not contain it, or it would read as a labelled clause plus an
/// unlabelled fragment.
const TRACE_PAGE_PARTIAL: &str = "trace_page_partial: this page is not the complete trace, and every original safety reading remains in the paged readings";

/// The single clause a partial reference page names as its limiting factor.
const REFERENCE_PAGE_PARTIAL: &str = "reference_page_partial: this page is not the complete answer, and every original safety reading remains in the paged readings";

impl Snapshot {
    fn shell(&self, cursor: &Cursor, next: &Cursor) -> Value {
        let has_more = next.record < self.records.len();
        let mut page = json!({
            "chain": [],
            "next_cursor": has_more.then(|| next.encode()),
            "_kin": {
                "envelope_version": 2,
                "runtime": "trace-snapshot",
                "verdict": {
                    "state": "inconclusive", "absence_claim": "not_claimed",
                    "safe_to_conclude_absent": false,
                    "limiting_factor": TRACE_PAGE_PARTIAL,
                    "original_state": self.original_verdict,
                },
                "completeness": {
                    "status": "partial", "bound": "at_least",
                    "counted": {"exact": false}, "limits": ["trace_page_partial"],
                },
                "page": {
                    "version": 1, "complete": false, "has_more": has_more,
                    "record_offset": cursor.record, "field_offset": cursor.field, "byte_offset": cursor.byte,
                    "next_record": next.record, "next_field": next.field, "next_byte": next.byte,
                    "total_records": self.records.len(),
                    "total_steps": self.total_steps,
                    "total_candidates": self.total_candidates,
                },
            },
            "negative": {
                "safe_to_conclude_absent": false,
                "interpretation": "qualified_answer", "subject": "trace_page",
            },
        });
        if self.kind == PageKind::References {
            page.as_object_mut().unwrap().remove("chain");
            page["references"] = json!([]);
            page["_kin"]["runtime"] = json!("reference-snapshot");
            page["_kin"]["verdict"]["limiting_factor"] = json!(REFERENCE_PAGE_PARTIAL);
            page["_kin"]["completeness"]["limits"] = json!(["reference_page_partial"]);
            page["_kin"]["page"]
                .as_object_mut()
                .unwrap()
                .remove("total_steps");
            page["_kin"]["page"]["kind"] = json!("references");
            page["_kin"]["page"]["total_references"] = json!(self.total_steps);
            page["negative"]["subject"] = json!("reference_page");
        }
        page["_kin"]
            .as_object_mut()
            .expect("page envelope")
            .extend(self.identity.clone());
        page
    }

    fn page(&self, cursor: Cursor, max_bytes: usize) -> Result<Value, String> {
        if max_bytes < crate::budget::RESPONSE_MIN_MAX_CHARS {
            return Err("trace page budget is below the tool floor".into());
        }
        if cursor.record >= self.records.len() {
            return Err("trace cursor is outside its snapshot; restart without cursor".into());
        }
        let mut next = cursor.clone();
        let mut page = self.shell(&cursor, &next);
        let mut kept = 0;
        if cursor.field == 0 && cursor.byte == 0 {
            for record in self.records.iter().skip(cursor.record) {
                let mut trial = page.clone();
                record.append_to(&mut trial);
                next.record += 1;
                update_page(&mut trial, &next, self.records.len(), max_bytes);
                if bytes(&trial) > max_bytes {
                    break;
                }
                page = trial;
                kept += 1;
            }
        }
        if kept > 0 {
            return Ok(page);
        }

        let record = &self.records[cursor.record];
        let fields: Vec<(Option<&str>, &Value)> = match &record.value {
            Value::Object(object) => object
                .iter()
                .map(|(key, value)| (Some(key.as_str()), value))
                .collect(),
            value => vec![(None, value)],
        };
        let Some((field, value)) = fields.get(cursor.field) else {
            return Err(
                "trace cursor field is outside its semantic record; restart without cursor".into(),
            );
        };
        let (encoding, encoded) = match value {
            Value::String(text) => ("utf8", text.clone()),
            value => (
                "json_utf8",
                serde_json::to_string(value).map_err(|error| error.to_string())?,
            ),
        };
        if cursor.byte > encoded.len()
            || (cursor.byte == encoded.len() && !encoded.is_empty())
            || !encoded.is_char_boundary(cursor.byte)
        {
            return Err(
                "trace fragment cursor is outside its semantic field; restart without cursor"
                    .into(),
            );
        }
        // Search code-point boundaries, measuring JSON escaping, cursor digits
        // and the complete compact envelope on every candidate. Source strings
        // are direct UTF-8 text; structured semantic fields identify their JSON
        // encoding explicitly. No whole row or reply is serialized as a stream.
        let boundaries: Vec<usize> = encoded[cursor.byte..]
            .char_indices()
            .skip(1)
            .map(|(offset, _)| cursor.byte + offset)
            .chain(std::iter::once(encoded.len()))
            .collect();
        let mut low = 0;
        let mut high = boundaries.len();
        let mut best = None;
        let mut try_complete = true;
        while low < high {
            let middle = if try_complete {
                high - 1
            } else {
                low + (high - low) / 2
            };
            try_complete = false;
            let end = boundaries[middle];
            let field_complete = end == encoded.len();
            let record_complete = field_complete && cursor.field + 1 == fields.len();
            let mut next = cursor.clone();
            if record_complete {
                next.record += 1;
                next.field = 0;
                next.byte = 0;
            } else if field_complete {
                next.field += 1;
                next.byte = 0;
            } else {
                next.byte = end;
            }
            let mut trial = self.shell(&cursor, &next);
            let mut fragment = record.identity();
            fragment["field"] = json!(field);
            fragment["encoding"] = json!(encoding);
            fragment["byte_offset"] = json!(cursor.byte);
            fragment["total_bytes"] = json!(encoded.len());
            fragment["field_complete"] = json!(field_complete);
            fragment["record_complete"] = json!(record_complete);
            fragment["text"] = json!(&encoded[cursor.byte..end]);
            trial["record_fragment"] = fragment;
            update_page(&mut trial, &next, self.records.len(), max_bytes);
            if bytes(&trial) <= max_bytes {
                best = Some(trial);
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        best.ok_or_else(|| "trace semantic record identity cannot fit the page budget".into())
    }
}

fn update_page(page: &mut Value, next: &Cursor, total: usize, max_bytes: usize) {
    let more = next.record < total;
    page["next_cursor"] = if more {
        json!(next.encode())
    } else {
        Value::Null
    };
    page["_kin"]["page"]["has_more"] = json!(more);
    page["_kin"]["page"]["next_record"] = json!(next.record);
    page["_kin"]["page"]["next_field"] = json!(next.field);
    page["_kin"]["page"]["next_byte"] = json!(next.byte);
    if page.pointer("/_kin/page/kind").and_then(Value::as_str) == Some("references") {
        page["_kin"]["page"]["returned_references"] =
            json!(page["references"].as_array().map_or(0, Vec::len));
    } else {
        page["total_steps"] = json!(page["chain"].as_array().map_or(0, Vec::len));
    }
    set_wire_size(page, max_bytes);
}

fn set_wire_size(page: &mut Value, max_bytes: usize) {
    page["_kin"]["response"] = json!({
        "max_chars": max_bytes, "chars_after_budget": 0,
        "bounded": page.pointer("/_kin/page/complete") != Some(&json!(true)),
        "compact": true,
    });
    for _ in 0..8 {
        let size = bytes(page);
        if page["_kin"]["response"]["chars_after_budget"] == size {
            break;
        }
        page["_kin"]["response"]["chars_after_budget"] = json!(size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    static TEST_CACHE: Mutex<()> = Mutex::new(());

    fn context(revision: u64) -> Context {
        Context::new(
            &json!({"focal":"start", "depth":3}),
            &json!({"repo":"a", "revision":revision}),
        )
    }

    fn payload() -> Value {
        json!({
            "focal_id": "00000000-0000-0000-0000-000000000000", "focal_name":"start",
            "chain": (1..=8).map(|step| json!({
                "step":step, "parent_step":step-1,
                "entity_id":format!("00000000-0000-0000-0000-{step:012}"),
                "entity_name":format!("hop_{step}"), "body":"λ\"\\\n".repeat(2000),
            })).collect::<Vec<_>>(),
            "total_steps":8,
            "_kin":{"envelope_version":2,
                "repository":{"root":"/example/project"},
                "graph_as_of":{"generation":7,"graph_root":"captured-root"},
                "runtime":"repo-daemon",
                "verdict":{"state":"inconclusive", "limiting_factor":"source_binding_unknown"}},
            "negative":{"safe_to_conclude_absent":false},
        })
    }

    #[test]
    fn fragments_preserve_every_byte_and_pages_fit_the_floor() {
        let _cache_test = TEST_CACHE.lock().unwrap();
        let original = payload();
        let mut page = start(original.clone(), context(1), 2000).unwrap();
        let mut reconstructed = serde_json::Map::new();
        let mut chains = Vec::new();
        let mut pending: BTreeMap<(String, usize, Option<String>), String> = BTreeMap::new();
        let mut partial_records: BTreeMap<(String, usize), serde_json::Map<String, Value>> =
            BTreeMap::new();
        let mut pages = 0;
        loop {
            pages += 1;
            assert!(pages < 1000);
            assert!(bytes(&page) <= 2000, "{}", bytes(&page));
            assert_eq!(page["_kin"]["response"]["chars_after_budget"], bytes(&page));
            assert_eq!(page["negative"]["safe_to_conclude_absent"], false);
            for key in ["repository", "graph_as_of", "runtime"] {
                assert_eq!(page["_kin"][key], original["_kin"][key]);
            }
            chains.extend(page["chain"].as_array().unwrap().iter().cloned());
            for reading in page["readings"].as_array().into_iter().flatten() {
                reconstructed.insert(
                    reading["key"].as_str().unwrap().to_string(),
                    reading["value"].clone(),
                );
            }
            if let Some(fragment) = page.get("record_fragment") {
                let collection = fragment["collection"].as_str().unwrap();
                let record_key = (
                    collection.to_string(),
                    fragment["index"].as_u64().unwrap() as usize,
                );
                let field = fragment["field"].as_str().map(str::to_string);
                let key = (record_key.0.clone(), record_key.1, field.clone());
                let accumulated = pending.entry(key.clone()).or_default();
                assert_eq!(
                    accumulated.len(),
                    fragment["byte_offset"].as_u64().unwrap() as usize
                );
                accumulated.push_str(fragment["text"].as_str().unwrap());
                if fragment["field_complete"] == true {
                    let value = if fragment["encoding"] == "utf8" {
                        json!(accumulated)
                    } else {
                        serde_json::from_str::<Value>(accumulated).unwrap()
                    };
                    pending.remove(&key);
                    let complete_value = if let Some(field) = field {
                        let record = partial_records.entry(record_key.clone()).or_default();
                        record.insert(field, value);
                        (fragment["record_complete"] == true)
                            .then(|| Value::Object(partial_records.remove(&record_key).unwrap()))
                    } else {
                        Some(value)
                    };
                    if let Some(value) = complete_value {
                        if collection == "chain" {
                            chains.push(value);
                        } else {
                            reconstructed
                                .insert(fragment["key"].as_str().unwrap().to_string(), value);
                        }
                    }
                }
            }
            let Some(token) = page["next_cursor"].as_str() else {
                break;
            };
            page = resume(token, &context(1), 2000).unwrap();
        }
        assert!(pending.is_empty());
        reconstructed.insert("chain".into(), json!(chains));
        assert_eq!(Value::Object(reconstructed), original);
    }

    #[test]
    fn complete_and_continued_tool_pages_keep_the_captured_repository_envelope() {
        let _cache_test = TEST_CACHE.lock().unwrap();
        for kind in [PageKind::Trace, PageKind::References] {
            for count in [0, 1, 50] {
                // Exercise the complete-answer path deliberately; the larger
                // fixture must continue under the narrower page budget.
                let ceiling = if count == 50 { 4000 } else { 60_000 };
                let mut envelope = crate::Envelope::daemon().with_repository(
                    &json!({"repo_root":"/example/selected"}),
                    Some(std::path::Path::new("/example/selected/nested")),
                    std::path::Path::to_path_buf,
                );
                let repository = serde_json::to_value(&envelope.repository).unwrap();
                let graph = json!({"generation":7,"graph_root":"selected-root"});
                envelope.graph_as_of = Some(graph.clone());
                let rows: Vec<_> = (0..count)
                    .map(|index| {
                        json!({
                            "entity_id": format!("entity-{index}"), "step": index,
                            "name": format!("caller_{index}"), "body":"x".repeat(350),
                        })
                    })
                    .collect();
                let mut raw = json!({"total_upstream":count,"total_steps":count});
                raw[kind.primary()] = json!(rows);
                let frozen = context(7);
                let result = finalize_kind(
                    crate::ToolCallResult::text(raw.to_string()),
                    envelope,
                    frozen.clone(),
                    ceiling,
                    kind,
                    false,
                );
                let crate::ContentBlock::Text { text } = &result.content[0];
                let mut page: Value = serde_json::from_str(text).unwrap();
                let mut pages = 0;
                loop {
                    pages += 1;
                    assert!(pages < 200);
                    assert_eq!(page["_kin"]["repository"], repository);
                    assert!(page["_kin"]["repository"]["warning"].is_string());
                    assert_eq!(page["_kin"]["graph_as_of"], graph);
                    assert_eq!(page["_kin"]["runtime"], "repo-daemon");
                    assert!(bytes(&page) <= ceiling);
                    if page["_kin"]["page"]["complete"] == false {
                        let factor = page["_kin"]["verdict"]["limiting_factor"]
                            .as_str()
                            .expect("a partial page names its limiting factor");
                        let clauses: Vec<_> =
                            factor.split(crate::verdict::CLAUSE_SEPARATOR).collect();
                        let code = match kind {
                            PageKind::Trace => "trace_page_partial",
                            PageKind::References => "reference_page_partial",
                        };
                        assert_eq!(clauses.len(), 1, "{factor}");
                        assert!(clauses[0].starts_with(code), "{factor}");
                    }

                    // The stdio finalizer receives another health reading.
                    // It must preserve the already-budgeted frozen answer.
                    let later = crate::Envelope::daemon().with_repository(
                        &json!({"repo_root":"/example/later"}),
                        None,
                        std::path::Path::to_path_buf,
                    );
                    let result = crate::envelope::finalize_bounded(
                        crate::ToolCallResult::text(page.to_string()),
                        later,
                        kind.tool(),
                        &crate::budget::ResponseBudget {
                            max_chars: ceiling,
                            ..Default::default()
                        },
                    );
                    let crate::ContentBlock::Text { text } = &result.content[0];
                    assert_eq!(serde_json::from_str::<Value>(text).unwrap(), page);
                    let Some(cursor) = page["next_cursor"].as_str() else {
                        break;
                    };
                    page = resume(cursor, &frozen, ceiling).unwrap();
                }
                if count == 50 {
                    assert!(pages > 1);
                } else {
                    assert_eq!(pages, 1);
                }
            }
        }
    }

    #[test]
    fn cursor_syntax_is_bounded_and_independent_of_snapshot_authority() {
        let cursor = Cursor {
            v: 1,
            snapshot: uuid::Uuid::nil(),
            record: usize::MAX,
            field: usize::MAX,
            byte: usize::MAX,
        };
        let token = cursor.encode();
        assert!(validate_cursor_syntax(&token).is_ok());
        assert!(resume(&token, &context(1), 2000)
            .unwrap_err()
            .contains("expired or was evicted"));
        for malformed in [
            "not-valid-here".to_string(),
            "x".repeat(MAX_CURSOR_BYTES + 1),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}"),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "v": 1, "snapshot": cursor.snapshot, "record": 0,
                    "field": 0, "byte": 0, "extra": true,
                }))
                .unwrap(),
            ),
            Cursor { v: 2, ..cursor }.encode(),
        ] {
            assert!(validate_cursor_syntax(&malformed).is_err(), "{malformed}");
        }
    }

    #[test]
    fn continuation_rejects_changed_authority_query_and_untrusted_offsets() {
        let _cache_test = TEST_CACHE.lock().unwrap();
        let page = start(payload(), context(7), 2000).unwrap();
        let token = page["next_cursor"].as_str().unwrap();
        assert!(resume(token, &context(8), 2000)
            .unwrap_err()
            .contains("authority"));
        let different_query = Context::new(
            &json!({"focal":"elsewhere"}),
            &json!({"repo":"a", "revision":7}),
        );
        assert!(resume(token, &different_query, 2000)
            .unwrap_err()
            .contains("query"));
        assert!(Cursor::decode(&"x".repeat(MAX_CURSOR_BYTES + 1)).is_err());
        let mut bad = Cursor::decode(token).unwrap();
        bad.record = usize::MAX;
        assert!(resume(&bad.encode(), &context(7), 2000).is_err());
    }

    #[test]
    fn continuation_binds_the_effective_outside_graph_question() {
        let _cache_test = TEST_CACHE.lock().unwrap();
        let mut arguments = std::collections::HashMap::from([
            ("focal".into(), json!("entry")),
            ("question".into(), json!("where is the external client")),
        ]);
        let authority = json!({"repo":"a", "revision":1});
        let context = Context::from_arguments(&arguments, &authority);
        let page = start(payload(), context.clone(), 2000).unwrap();
        let token = page["next_cursor"].as_str().unwrap();
        arguments.insert("question".into(), json!("where is another client"));
        assert!(resume(
            token,
            &Context::from_arguments(&arguments, &authority),
            2000
        )
        .unwrap_err()
        .contains("query"));
        arguments.insert("query".into(), json!(" where is the external client "));
        assert!(resume(
            token,
            &Context::from_arguments(&arguments, &authority),
            2000
        )
        .is_ok());
        arguments.insert(
            CLIENT_ROOT_ARGUMENT.into(),
            json!("/example/different-folder"),
        );
        assert!(resume(
            token,
            &Context::from_arguments(&arguments, &authority),
            2000
        )
        .unwrap_err()
        .contains("query"));
    }

    #[test]
    fn hosted_focal_fragments_keep_canonical_entity_and_absolute_step() {
        let record = Record {
            collection: "readings",
            index: 0,
            key: Some("focal_entity".into()),
            value: json!({"id":"entity-1", "body":"source"}),
        };
        assert_eq!(
            record.identity(),
            json!({"collection":"readings", "index":0,
            "key":"focal_entity", "entity_id":"entity-1", "step":0, "parent_step":0})
        );
    }

    #[test]
    fn normal_step_prefix_is_monotonic_in_the_budget() {
        let _cache_test = TEST_CACHE.lock().unwrap();
        let mut original = payload();
        for row in original["chain"].as_array_mut().unwrap() {
            row["body"] = json!("small".repeat(30));
        }
        let mut before = 0;
        for ceiling in (2000..=16000).step_by(250) {
            let page = start(original.clone(), context(1), ceiling).unwrap();
            let count = page["chain"].as_array().unwrap().len();
            assert!(count >= before, "{ceiling}: {count} after {before}");
            assert!(bytes(&page) <= ceiling);
            before = count;
        }
        assert_eq!(before, 8);
    }
    #[test]
    fn cache_expiry_and_entry_pressure_require_an_explicit_restart() {
        let _cache_test = TEST_CACHE.lock().unwrap();
        let page = start(payload(), context(1), 2000).unwrap();
        let token = page["next_cursor"].as_str().unwrap().to_string();
        for _ in 0..MAX_CACHE_ENTRIES {
            start(payload(), context(1), 2000).unwrap();
        }
        assert!(resume(&token, &context(1), 2000)
            .unwrap_err()
            .contains("evicted"));
        let page = start(payload(), context(1), 2000).unwrap();
        let token = page["next_cursor"].as_str().unwrap().to_string();
        cache()
            .lock()
            .unwrap()
            .expire(Instant::now() + SNAPSHOT_TTL);
        assert!(resume(&token, &context(1), 2000)
            .unwrap_err()
            .contains("expired"));
    }

    #[test]
    fn ambiguity_pages_preserve_every_candidate_and_final_page_remains_qualified() {
        let _cache_test = TEST_CACHE.lock().unwrap();
        let candidates: Vec<_> = (0..150)
            .map(|index| {
                json!({
                    "entity_id":format!("00000000-0000-0000-0000-{index:012}"),
                    "name":format!("Owner{index}.get"), "file":format!("module_{index}.py"),
                })
            })
            .collect();
        let value = json!({"ambiguous_focal":true, "candidate_count":candidates.len(), "candidates":candidates});
        let mut page = start(value, context(1), 2000).unwrap();
        let mut served = Vec::new();
        loop {
            assert!(bytes(&page) <= 2000);
            served.extend(page["candidates"].as_array().into_iter().flatten().cloned());
            assert_eq!(page["negative"]["safe_to_conclude_absent"], false);
            let Some(cursor) = page["next_cursor"].as_str() else {
                break;
            };
            page = resume(cursor, &context(1), 2000).unwrap();
        }
        assert_eq!(served, candidates);
    }

    #[test]
    fn full_envelope_preparation_does_not_drop_requested_bodies() {
        let _cache_test = TEST_CACHE.lock().unwrap();
        let source = payload();
        let result = finalize(
            crate::ToolCallResult::text(source.to_string()),
            crate::Envelope::offline(),
            context(1),
            2000,
        );
        let crate::ContentBlock::Text { text } = &result.content[0];
        let mut page: Value = serde_json::from_str(text).unwrap();
        let mut bodies: BTreeMap<usize, String> = BTreeMap::new();
        loop {
            assert!(bytes(&page) <= 2000);
            if page["record_fragment"]["collection"] == "chain"
                && page["record_fragment"]["field"] == "body"
            {
                let fragment = &page["record_fragment"];
                assert_eq!(fragment["encoding"], "utf8");
                bodies
                    .entry(fragment["index"].as_u64().unwrap() as usize)
                    .or_default()
                    .push_str(fragment["text"].as_str().unwrap());
            }
            let Some(cursor) = page["next_cursor"].as_str() else {
                break;
            };
            page = resume(cursor, &context(1), 2000).unwrap();
        }
        assert_eq!(bodies.len(), 8);
        for (index, body) in bodies {
            assert_eq!(source["chain"][index]["body"], body);
        }
    }
}
