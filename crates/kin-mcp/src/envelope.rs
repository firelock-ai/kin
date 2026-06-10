// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Versioned MCP response envelope (D.8).
//!
//! Every MCP tool response is annotated with one additive, versioned metadata
//! object under the reserved top-level key [`ENVELOPE_KEY`] (`_kin`). One
//! envelope shape is shared by all tool families so an agent reads trust
//! metadata the same way regardless of which tool answered. The envelope
//! carries:
//!
//! - the envelope schema version,
//! - the runtime that answered (daemon-owned graph vs explicit offline path),
//! - `semantic_coverage` in the same shape `kin locate --json` / `kin status`
//!   report, lifted from the tool payload when the daemon already included it,
//! - graph freshness (`graph_as_of` plus honest `/health`-derived state),
//! - degraded flags: daemon-unreachable, `embed_worker_failed` (#11),
//!   `mass_deletion_blocked`, and offline-fallback.
//!
//! Honesty contract (CLAUDE.md): the envelope NEVER fabricates coverage or
//! freshness. Anything it cannot observe is `null`/absent, not a default `false`
//! or a zeroed count. Degraded flags are `Some(bool)` only when actually
//! observed (e.g. parsed from the daemon `/health` body); otherwise they are
//! omitted rather than asserted `false`.
//!
//! ## Back-compat
//!
//! The envelope is purely additive. For the common case — a tool whose payload
//! is a JSON object — the original payload keys are left exactly where agents
//! expect them and `_kin` is added alongside. Payloads that are not JSON objects
//! (arrays, scalars, or human-readable error text) are wrapped so the envelope
//! still rides along without losing the original content.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::types::{ContentBlock, ToolCallResult};

/// Current envelope schema version. Bump on any breaking field change so
/// Kin-aware consumers can detect and adapt to envelope evolution.
pub const ENVELOPE_VERSION: u32 = 1;

/// Reserved top-level key the envelope is attached under. Distinctive and
/// namespaced so it never collides with a tool payload's own fields.
pub const ENVELOPE_KEY: &str = "_kin";

/// Which runtime produced a tool response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    /// Product path: forwarded to the repo daemon's live, graph-owned truth.
    RepoDaemon,
    /// Explicit offline/test path: an in-process graph store, no daemon. Per the
    /// graph-first thesis this is a fallback surface, not steady-state.
    OfflineInProcess,
}

/// Embedding (semantic signal) coverage, mirroring the `SemanticCoverage` shape
/// kin-cli's locate/status surfaces report (`indexed`/`total`/`pending`/
/// `complete`/`note`) so an agent reads readiness identically from MCP or CLI.
///
/// Only populated when the tool payload carried it (the daemon already computes
/// it for locate/search from its live graph). Never fabricated here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticCoverage {
    /// Entities with an embedding indexed in the vector store.
    pub indexed: u64,
    /// Total entities eligible for embedding.
    pub total: u64,
    /// Entities still queued for embedding.
    pub pending: u64,
    /// True when the semantic signal was complete (`total == 0`, or every entity
    /// indexed with nothing pending).
    pub complete: bool,
    /// Human-readable note describing the degraded state, present only when the
    /// semantic signal was partial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl SemanticCoverage {
    /// Lift a `semantic_coverage` object out of a tool payload, validating the
    /// shape. Returns `None` when the payload has no such field or it is not the
    /// expected object — we surface `unknown` rather than guessing.
    fn from_payload_field(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        Some(SemanticCoverage {
            indexed: obj.get("indexed").and_then(Value::as_u64)?,
            total: obj.get("total").and_then(Value::as_u64)?,
            pending: obj.get("pending").and_then(Value::as_u64)?,
            complete: obj.get("complete").and_then(Value::as_bool)?,
            note: obj.get("note").and_then(Value::as_str).map(str::to_string),
        })
    }
}

/// Honest degraded-state flags. Each is `Some(bool)` only when observed and
/// `None` (serialized absent) when the envelope could not determine it — never a
/// fabricated `false`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Degraded {
    /// The daemon was required but unreachable; the result is a transport error
    /// rather than graph-owned truth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_unreachable: Option<bool>,
    /// Daemon `/health`: the background embedding worker has permanently stopped
    /// (#11). The graph still serves; the vector index is frozen until restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embed_worker_failed: Option<bool>,
    /// Daemon `/health`: a suspected mass-deletion wipe is being withheld pending
    /// operator confirmation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mass_deletion_blocked: Option<bool>,
    /// The response came from the explicit offline/in-process path rather than
    /// daemon-owned truth (graph-first: a fallback surface).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_fallback: Option<bool>,
}

impl Degraded {
    /// True when any degraded condition is affirmatively set.
    pub fn any(&self) -> bool {
        [
            self.daemon_unreachable,
            self.embed_worker_failed,
            self.mass_deletion_blocked,
            self.offline_fallback,
        ]
        .into_iter()
        .any(|flag| flag == Some(true))
    }
}

/// Graph freshness context — what graph state answered the query. `as_of` is a
/// precise version marker only when the payload/daemon provides one; the rest
/// are honest `/health`-derived signals (never fabricated).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GraphState {
    /// Daemon `/health` reconciliation status (e.g. `"clean"`, `"reconciling"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_status: Option<String>,
    /// Daemon-reported entity count at answer time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_count: Option<u64>,
    /// Whether the daemon has a graph loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    /// Whether the daemon has completed first reconciliation / snapshot load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initialized: Option<bool>,
}

impl GraphState {
    fn is_empty(&self) -> bool {
        self.reconciliation_status.is_none()
            && self.entity_count.is_none()
            && self.loaded.is_none()
            && self.initialized.is_none()
    }
}

/// The versioned MCP response envelope shared by every tool family.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    /// Schema version of this envelope ([`ENVELOPE_VERSION`]).
    pub envelope_version: u32,
    /// Runtime that produced the response.
    pub runtime: Runtime,
    /// Embedding coverage when known; `null`/absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_coverage: Option<SemanticCoverage>,
    /// Precise graph version marker when known; `null`/absent otherwise. The
    /// daemon `/health` surface does not yet expose a generation/content marker,
    /// so this is only populated when a tool payload carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_as_of: Option<Value>,
    /// Honest graph freshness context; omitted entirely when nothing is known.
    #[serde(default, skip_serializing_if = "GraphState::is_empty")]
    pub graph_state: GraphState,
    /// Degraded-state flags (always present; individual flags omitted when not
    /// observed).
    pub degraded: Degraded,
}

impl Envelope {
    /// Envelope for the explicit offline/in-process runtime. Flags
    /// `offline_fallback` honestly — this is not daemon-owned truth.
    pub fn offline() -> Self {
        Self {
            envelope_version: ENVELOPE_VERSION,
            runtime: Runtime::OfflineInProcess,
            semantic_coverage: None,
            graph_as_of: None,
            graph_state: GraphState::default(),
            degraded: Degraded {
                offline_fallback: Some(true),
                ..Degraded::default()
            },
        }
    }

    /// Envelope for a daemon-answered response. Degraded flags start empty and
    /// are filled in honestly from the daemon `/health` body via
    /// [`Envelope::with_health`].
    pub fn daemon() -> Self {
        Self {
            envelope_version: ENVELOPE_VERSION,
            runtime: Runtime::RepoDaemon,
            semantic_coverage: None,
            graph_as_of: None,
            graph_state: GraphState::default(),
            degraded: Degraded::default(),
        }
    }

    /// Envelope for the case where the daemon was required but unreachable. The
    /// accompanying tool result is a transport error; this flags it structurally.
    pub fn daemon_unreachable() -> Self {
        Self {
            envelope_version: ENVELOPE_VERSION,
            runtime: Runtime::RepoDaemon,
            semantic_coverage: None,
            graph_as_of: None,
            graph_state: GraphState::default(),
            degraded: Degraded {
                daemon_unreachable: Some(true),
                ..Degraded::default()
            },
        }
    }

    /// Fold honest signals from a daemon `/health` JSON body into the envelope:
    /// the `embed_worker_failed` / `mass_deletion_blocked` degraded flags and the
    /// graph freshness state. Missing fields stay unknown (absent), never
    /// fabricated.
    pub fn with_health(mut self, health: &Value) -> Self {
        if let Some(value) = health.get("embed_worker_failed").and_then(Value::as_bool) {
            self.degraded.embed_worker_failed = Some(value);
        }
        if let Some(value) = health.get("mass_deletion_blocked").and_then(Value::as_bool) {
            self.degraded.mass_deletion_blocked = Some(value);
        }
        if let Some(value) = health.get("reconciliation_status").and_then(Value::as_str) {
            self.graph_state.reconciliation_status = Some(value.to_string());
        }
        if let Some(value) = health.get("graph_entity_count").and_then(Value::as_u64) {
            self.graph_state.entity_count = Some(value);
        }
        if let Some(value) = health.get("graph_loaded").and_then(Value::as_bool) {
            self.graph_state.loaded = Some(value);
        }
        if let Some(value) = health.get("initialized").and_then(Value::as_bool) {
            self.graph_state.initialized = Some(value);
        }
        self
    }

    /// Lift `semantic_coverage` and `graph_as_of` out of a tool payload when the
    /// daemon already computed them, so they live in one predictable place on the
    /// envelope. Absent fields stay unknown.
    pub fn with_payload_metadata(mut self, payload: &Value) -> Self {
        if self.semantic_coverage.is_none() {
            if let Some(coverage) = payload
                .get("semantic_coverage")
                .and_then(SemanticCoverage::from_payload_field)
            {
                self.semantic_coverage = Some(coverage);
            }
        }
        if self.graph_as_of.is_none() {
            for key in ["graph_as_of", "as_of"] {
                if let Some(marker) = payload.get(key) {
                    if !marker.is_null() {
                        self.graph_as_of = Some(marker.clone());
                        break;
                    }
                }
            }
        }
        self
    }

    /// Serialize the envelope to a JSON value for embedding under [`ENVELOPE_KEY`].
    fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Annotate a tool result with the envelope under [`ENVELOPE_KEY`].
///
/// - Object payloads keep every existing key in place; `_kin` is added alongside
///   (the back-compat common case). An existing `_kin` is never clobbered.
/// - Non-object JSON payloads (arrays/scalars) are wrapped as
///   `{ "_kin": <envelope>, "result": <payload> }`.
/// - Human-readable text (e.g. error messages that are not JSON) is wrapped as
///   `{ "_kin": <envelope>, "message": <text> }`, preserving the message.
///
/// `is_error` and any non-text content blocks are preserved unchanged.
pub fn annotate(result: ToolCallResult, envelope: &Envelope) -> ToolCallResult {
    let envelope_value = envelope.to_value();
    let content = result
        .content
        .into_iter()
        .map(|block| annotate_block(block, &envelope_value))
        .collect();
    ToolCallResult {
        content,
        is_error: result.is_error,
    }
}

/// Extract the first text content block's payload as JSON, when it parses.
fn first_payload_value(result: &ToolCallResult) -> Option<Value> {
    result.content.iter().find_map(|block| {
        let ContentBlock::Text { text } = block;
        serde_json::from_str::<Value>(text).ok()
    })
}

/// The single call sites use to attach the envelope: lift any metadata the tool
/// payload already carries (`semantic_coverage`, `graph_as_of`) into `base`,
/// then annotate the result under [`ENVELOPE_KEY`]. Keeping lift + annotate
/// together means every dispatch path produces a consistently-enriched envelope.
pub fn finalize(result: ToolCallResult, base: Envelope) -> ToolCallResult {
    let envelope = match first_payload_value(&result) {
        Some(payload) => base.with_payload_metadata(&payload),
        None => base,
    };
    annotate(result, &envelope)
}

fn annotate_block(block: ContentBlock, envelope_value: &Value) -> ContentBlock {
    let ContentBlock::Text { text } = block;
    let annotated = match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(mut map)) => {
            map.entry(ENVELOPE_KEY.to_string())
                .or_insert_with(|| envelope_value.clone());
            Value::Object(map)
        }
        Ok(other) => {
            let mut map = Map::new();
            map.insert(ENVELOPE_KEY.to_string(), envelope_value.clone());
            map.insert("result".to_string(), other);
            Value::Object(map)
        }
        Err(_) => {
            let mut map = Map::new();
            map.insert(ENVELOPE_KEY.to_string(), envelope_value.clone());
            map.insert("message".to_string(), Value::String(text));
            Value::Object(map)
        }
    };
    let rendered =
        serde_json::to_string_pretty(&annotated).unwrap_or_else(|_| annotated.to_string());
    ContentBlock::Text { text: rendered }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_of(result: &ToolCallResult) -> Value {
        let ContentBlock::Text { text } = result.content.first().expect("one content block");
        let value: Value = serde_json::from_str(text).expect("annotated payload is JSON");
        value
            .get(ENVELOPE_KEY)
            .cloned()
            .expect("annotated payload carries _kin envelope")
    }

    #[test]
    fn offline_envelope_flags_fallback_and_version() {
        let env = Envelope::offline();
        assert_eq!(env.envelope_version, ENVELOPE_VERSION);
        assert_eq!(env.runtime, Runtime::OfflineInProcess);
        assert_eq!(env.degraded.offline_fallback, Some(true));
        // Honesty: nothing observed about coverage/freshness offline.
        assert!(env.semantic_coverage.is_none());
        assert!(env.graph_state.is_empty());
    }

    #[test]
    fn daemon_unreachable_envelope_sets_flag() {
        let env = Envelope::daemon_unreachable();
        assert_eq!(env.runtime, Runtime::RepoDaemon);
        assert_eq!(env.degraded.daemon_unreachable, Some(true));
        assert!(env.degraded.any());
    }

    #[test]
    fn with_health_folds_degraded_and_state_honestly() {
        let health = serde_json::json!({
            "status": "attention",
            "embed_worker_failed": true,
            "mass_deletion_blocked": false,
            "reconciliation_status": "clean",
            "graph_entity_count": 1234,
            "graph_loaded": true,
            "initialized": true,
        });
        let env = Envelope::daemon().with_health(&health);
        assert_eq!(env.degraded.embed_worker_failed, Some(true));
        assert_eq!(env.degraded.mass_deletion_blocked, Some(false));
        assert_eq!(
            env.graph_state.reconciliation_status.as_deref(),
            Some("clean")
        );
        assert_eq!(env.graph_state.entity_count, Some(1234));
        assert_eq!(env.graph_state.loaded, Some(true));
        assert_eq!(env.graph_state.initialized, Some(true));
        assert!(env.degraded.any());
    }

    #[test]
    fn with_health_missing_fields_stay_unknown() {
        // An empty/partial health body must not fabricate `false`/`0` values.
        let env = Envelope::daemon().with_health(&serde_json::json!({}));
        assert!(env.degraded.embed_worker_failed.is_none());
        assert!(env.degraded.mass_deletion_blocked.is_none());
        assert!(env.graph_state.is_empty());
        assert!(!env.degraded.any());
    }

    #[test]
    fn with_payload_metadata_lifts_coverage_and_as_of() {
        let payload = serde_json::json!({
            "results": [],
            "semantic_coverage": {
                "indexed": 10, "total": 20, "pending": 5, "complete": false,
                "note": "partial",
            },
            "as_of": "change:abcdef",
        });
        let env = Envelope::daemon().with_payload_metadata(&payload);
        let coverage = env.semantic_coverage.expect("coverage lifted");
        assert_eq!(coverage.indexed, 10);
        assert_eq!(coverage.total, 20);
        assert_eq!(coverage.pending, 5);
        assert!(!coverage.complete);
        assert_eq!(coverage.note.as_deref(), Some("partial"));
        assert_eq!(env.graph_as_of, Some(serde_json::json!("change:abcdef")));
    }

    #[test]
    fn with_payload_metadata_ignores_malformed_coverage() {
        // A coverage field that is not the expected object shape is treated as
        // unknown, not partially fabricated.
        let payload = serde_json::json!({ "semantic_coverage": "n/a" });
        let env = Envelope::daemon().with_payload_metadata(&payload);
        assert!(env.semantic_coverage.is_none());
    }

    #[test]
    fn annotate_object_payload_adds_kin_in_place() {
        let result = ToolCallResult::text(
            serde_json::to_string(&serde_json::json!({ "results": [1, 2, 3] })).unwrap(),
        );
        let annotated = annotate(result, &Envelope::offline());
        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let value: Value = serde_json::from_str(text).unwrap();
        // Original key stays exactly where agents expect it.
        assert_eq!(value["results"], serde_json::json!([1, 2, 3]));
        // Envelope rides alongside.
        assert_eq!(value[ENVELOPE_KEY]["envelope_version"], ENVELOPE_VERSION);
        assert_eq!(value[ENVELOPE_KEY]["runtime"], "offline-in-process");
    }

    #[test]
    fn annotate_does_not_clobber_existing_kin() {
        let result = ToolCallResult::text(
            serde_json::to_string(&serde_json::json!({ "_kin": "preexisting" })).unwrap(),
        );
        let annotated = annotate(result, &Envelope::offline());
        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(value[ENVELOPE_KEY], serde_json::json!("preexisting"));
    }

    #[test]
    fn annotate_array_payload_wraps_under_result() {
        let result =
            ToolCallResult::text(serde_json::to_string(&serde_json::json!([1, 2])).unwrap());
        let annotated = annotate(result, &Envelope::offline());
        let value = envelope_of(&annotated);
        assert_eq!(value["envelope_version"], ENVELOPE_VERSION);
        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let whole: Value = serde_json::from_str(text).unwrap();
        assert_eq!(whole["result"], serde_json::json!([1, 2]));
    }

    #[test]
    fn annotate_plain_text_error_wraps_under_message_and_preserves_is_error() {
        let result = ToolCallResult::error("daemon is unreachable");
        assert_eq!(result.is_error, Some(true));
        let annotated = annotate(result, &Envelope::daemon_unreachable());
        // Error flag survives annotation.
        assert_eq!(annotated.is_error, Some(true));
        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let whole: Value = serde_json::from_str(text).unwrap();
        assert_eq!(whole["message"], serde_json::json!("daemon is unreachable"));
        assert_eq!(whole[ENVELOPE_KEY]["degraded"]["daemon_unreachable"], true);
        // Human substring is still findable inside the wrapped JSON.
        assert!(text.contains("daemon is unreachable"));
    }

    #[test]
    fn envelope_omits_unknown_fields_when_serialized() {
        // The offline envelope should not serialize null coverage / empty state.
        let value = Envelope::offline().to_value();
        let obj = value.as_object().unwrap();
        assert!(!obj.contains_key("semantic_coverage"));
        assert!(!obj.contains_key("graph_as_of"));
        assert!(!obj.contains_key("graph_state"));
        // degraded is always present.
        assert!(obj.contains_key("degraded"));
    }
}
