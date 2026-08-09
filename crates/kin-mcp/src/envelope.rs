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
use serde_json::{json, Map, Value};

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

    /// The names of the degraded signals that are affirmatively set, in a stable
    /// order. Used to spell out "degraded signals Z" in a confidence-qualified
    /// negative without fabricating flags that were never observed.
    pub fn active_labels(&self) -> Vec<&'static str> {
        let mut labels = Vec::new();
        if self.daemon_unreachable == Some(true) {
            labels.push("daemon_unreachable");
        }
        if self.embed_worker_failed == Some(true) {
            labels.push("embed_worker_failed");
        }
        if self.mass_deletion_blocked == Some(true) {
            labels.push("mass_deletion_blocked");
        }
        if self.offline_fallback == Some(true) {
            labels.push("offline_fallback");
        }
        labels
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

/// Which completeness gate governs whether an *absent* result can be trusted as
/// a definitive negative. Different retrieval families depend on different
/// substrates, so "is the index complete enough to trust an empty answer?" has
/// two different answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegativeClass {
    /// Embedding-backed retrieval (`semantic_locate`, `semantic_search`). An
    /// empty result is only authoritative when *embedding* coverage is complete —
    /// a half-embedded graph can hide a match that exists.
    Semantic,
    /// Graph-structure-backed retrieval (`find_references`, `graph_neighborhood`,
    /// `trace_data_flow`, `dead_code`, `find_dead_code_seeded`, `entity_history`,
    /// `bulk_check_references`). These read typed graph relations, not embeddings,
    /// so their absence-trust depends on the *graph* being initialized and loaded,
    /// not on embedding coverage.
    Structural,
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
    /// Precise graph version marker when known; `null`/absent otherwise. Populated
    /// from the daemon `/health` `graph_generation` marker (the monotonic snapshot
    /// generation, bumped per committed snapshot) via [`Envelope::with_health`], or
    /// from a tool payload's own `graph_as_of`/`as_of` marker when one is carried.
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

    /// Bind the stdio response envelope to the same selected-graph observation
    /// carried by `kin.graph-status.v1`.
    ///
    /// Generic daemon responses enrich their envelope from `/health`. That
    /// endpoint is HEAD-scoped, so using it for a temporal-session graph status
    /// would mix two graph views in one payload. Graph status instead supplies
    /// its own entity and embedding observations here. Fields that only
    /// `/health` knows stay absent rather than being borrowed from HEAD.
    pub fn with_selected_graph_observation(
        mut self,
        entity_count: u64,
        embeddings_indexed: u64,
        embeddings_pending: u64,
        embeddings_total: u64,
    ) -> Self {
        let complete = embeddings_pending == 0 && embeddings_indexed == embeddings_total;
        self.runtime = Runtime::RepoDaemon;
        self.semantic_coverage = Some(SemanticCoverage {
            indexed: embeddings_indexed,
            total: embeddings_total,
            pending: embeddings_pending,
            complete,
            note: (!complete).then(|| {
                "Selected-graph embedding coverage is incomplete at this point-in-time observation."
                    .to_string()
            }),
        });
        self.graph_as_of = None;
        self.graph_state = GraphState {
            entity_count: Some(entity_count),
            ..GraphState::default()
        };
        self.degraded = Degraded::default();
        self
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
        // The daemon `/health` `graph_generation` marker (monotonic snapshot
        // generation, bumped per committed snapshot) is a precise freshness
        // marker: lift it into `graph_as_of` so a negative can say *which* graph
        // answered. A tool payload's own marker, if one is later carried, still
        // wins (the `is_none` guard leaves a payload-lifted value untouched).
        if self.graph_as_of.is_none() {
            if let Some(generation) = health.get("graph_generation").and_then(Value::as_u64) {
                self.graph_as_of = Some(json!({ "generation": generation }));
            }
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

    /// Whether an "absent" answer from a tool of the given [`NegativeClass`] can
    /// be trusted as a definitive negative, with the machine-stable reason naming
    /// *which gate ruled*.
    ///
    /// This is the epistemic core of the confidence-qualified-negative contract:
    /// a "not found" is only distinguishable from "not indexed" when the answer
    /// came from daemon-owned truth (`RepoDaemon`) with no degraded signals **and**
    /// the substrate the tool actually reads is complete. The two runtime/degraded
    /// gates are shared; the completeness gate is class-specific:
    ///
    /// - [`NegativeClass::Semantic`] tools read embeddings, so absence is
    ///   authoritative only with **complete embedding coverage**.
    /// - [`NegativeClass::Structural`] tools read typed graph relations, so absence
    ///   is authoritative when the daemon **graph is initialized and loaded** —
    ///   embedding coverage is irrelevant to them.
    ///
    /// The reason is honest about which gate held and never claims authority the
    /// envelope did not actually observe.
    pub fn negative_trust(&self, class: NegativeClass) -> (bool, &'static str) {
        if self.runtime != Runtime::RepoDaemon {
            return (
                false,
                "offline_fallback: answered by the in-process graph, a fallback surface — not authoritative graph truth",
            );
        }
        if self.degraded.any() {
            return (
                false,
                "degraded: the daemon reported a degraded signal, so the index may not reflect current truth",
            );
        }
        match class {
            NegativeClass::Semantic => match &self.semantic_coverage {
                None => (
                    false,
                    "coverage_unknown: embedding coverage was not reported, so an empty result may mean 'not indexed' rather than 'not present'",
                ),
                Some(coverage) if !coverage.complete => (
                    false,
                    "coverage_partial: the semantic index is incomplete, so an empty result may mean 'not indexed' rather than 'not present'",
                ),
                Some(_) => (
                    true,
                    "semantic_authoritative: daemon-owned truth with complete embedding coverage and no degraded signals",
                ),
            },
            NegativeClass::Structural => {
                if self.graph_state.initialized != Some(true) {
                    (
                        false,
                        "graph_uninitialized: the daemon has not confirmed first reconciliation/snapshot load, so an empty structural result may mean the graph is not yet complete",
                    )
                } else if self.graph_state.loaded != Some(true) {
                    (
                        false,
                        "graph_not_loaded: the daemon reports no graph loaded, so an empty structural result is not authoritative",
                    )
                } else {
                    (
                        true,
                        "structural_authoritative: daemon graph initialized and loaded with no degraded signals",
                    )
                }
            }
        }
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
    annotate_inner(result, envelope, None)
}

/// Like [`annotate`], but also attaches a confidence-qualified `negative` object
/// alongside `_kin` when one was synthesized for the tool. The negative rides
/// the same content block as the envelope so an agent reads both from one place.
/// A pre-existing `negative` key is never clobbered.
fn annotate_inner(
    result: ToolCallResult,
    envelope: &Envelope,
    negative: Option<&Value>,
) -> ToolCallResult {
    let envelope_value = envelope.to_value();
    let content = result
        .content
        .into_iter()
        .map(|block| annotate_block(block, &envelope_value, negative))
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

/// The first text content block verbatim. This is what a failed call carries
/// instead of a payload: human-readable text that [`annotate_block`] preserves
/// under `message`.
fn first_message_text(result: &ToolCallResult) -> Option<&str> {
    result.content.first().map(|block| {
        let ContentBlock::Text { text } = block;
        text.as_str()
    })
}

/// The single call sites use to attach the envelope: lift any metadata the tool
/// payload already carries (`semantic_coverage`, `graph_as_of`) into `base`,
/// synthesize a confidence-qualified `negative` for retrieval tools that came
/// back empty, then annotate the result under [`ENVELOPE_KEY`]. Keeping
/// lift + qualify + annotate together in one chokepoint means every dispatch
/// path (offline and daemon) produces a consistently-enriched envelope and an
/// identical negative contract regardless of which runtime answered.
///
/// A retrieval tool has two ways of reporting "nothing", and only one of them
/// carries a payload. When the name a caller passed resolves to no entity the
/// answer is a human message with no collection to count, which used to reach
/// the agent as a bare `{"message": ...}` beside the envelope while every
/// resolved answer from the same tool carried a full negative. That asymmetry
/// is the one an agent cannot see, so the miss is qualified here too.
pub fn finalize(result: ToolCallResult, base: Envelope, tool_name: &str) -> ToolCallResult {
    let payload = first_payload_value(&result);
    let envelope = match &payload {
        Some(payload) => base.with_payload_metadata(payload),
        None => base,
    };
    let negative = match &payload {
        Some(payload) => crate::negative::negative_for(tool_name, payload, &envelope),
        None if result.is_error == Some(true) => first_message_text(&result)
            .and_then(|message| crate::negative::resolution_miss_for(tool_name, message, &envelope)),
        None => None,
    };
    annotate_inner(result, &envelope, negative.as_ref())
}

fn annotate_block(
    block: ContentBlock,
    envelope_value: &Value,
    negative: Option<&Value>,
) -> ContentBlock {
    let ContentBlock::Text { text } = block;
    let annotated = match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(mut map)) => {
            map.entry(ENVELOPE_KEY.to_string())
                .or_insert_with(|| envelope_value.clone());
            if let Some(negative) = negative {
                map.entry(crate::negative::NEGATIVE_KEY.to_string())
                    .or_insert_with(|| negative.clone());
            }
            Value::Object(map)
        }
        Ok(other) => {
            let mut map = Map::new();
            map.insert(ENVELOPE_KEY.to_string(), envelope_value.clone());
            if let Some(negative) = negative {
                map.insert(crate::negative::NEGATIVE_KEY.to_string(), negative.clone());
            }
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
    fn with_health_lifts_graph_generation_into_graph_as_of() {
        // 621af29 added `graph_generation` to /health; the envelope lifts that
        // monotonic snapshot marker into `graph_as_of` so a negative can name
        // which graph snapshot answered.
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_loaded": true,
            "initialized": true,
            "graph_generation": 7,
        }));
        assert_eq!(
            env.graph_as_of,
            Some(serde_json::json!({ "generation": 7 }))
        );
    }

    #[test]
    fn with_health_without_generation_leaves_graph_as_of_unknown() {
        // Honesty: no marker reported => graph_as_of stays absent, never fabricated.
        let env = Envelope::daemon().with_health(&serde_json::json!({ "graph_loaded": true }));
        assert!(env.graph_as_of.is_none());
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
