// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Confidence-qualified negatives (Track C trust contract).
//!
//! For an agent, the epistemics of a "no result" matter as much as the result
//! itself: a bare empty array cannot tell "this symbol genuinely has no
//! references" (safe to delete) from "the graph has not finished indexing"
//! (absolutely not safe to delete). Retrieval tools used to return those two
//! cases identically.
//!
//! This module turns an empty (or, for batch reachability, a verdict-bearing)
//! retrieval response into an explicit, additive `negative` object that carries
//! the freshness and coverage context lifted onto the [`Envelope`], plus a
//! single derived verdict — `safe_to_conclude_absent` — so an agent can
//! calibrate trust in one read.
//!
//! ## Single source of truth
//!
//! [`spec_for`] is the one registry of which tools are negative-capable and how
//! each expresses "no result". [`negative_for`] is folded into
//! `envelope::finalize`, the single annotation chokepoint, so the contract is
//! identical on the offline and daemon paths — no per-handler edits, no shape
//! drift.
//!
//! ## Honesty contract (CLAUDE.md)
//!
//! Every value in the negative is derived from what the envelope actually
//! observed. Unknown freshness/coverage is `null` and forces
//! `safe_to_conclude_absent = false` — absence is never certified on data the
//! envelope did not see.

use serde_json::{json, Map, Value};

use crate::envelope::{Envelope, NegativeClass};

/// Reserved, additive top-level key under which a retrieval tool's
/// confidence-qualified negative is attached, beside the `_kin` envelope.
/// Distinctive enough not to collide with any tool payload's own fields.
pub const NEGATIVE_KEY: &str = "negative";

/// How one tool's payload expresses "no result", and how to frame the resulting
/// negative. One row per negative-capable tool — the single source of truth.
struct RetrievalSpec {
    /// Object key holding the result collection. `""` means the payload is a
    /// bare JSON array (wrapped under `result` by the envelope annotator).
    field: &'static str,
    /// Machine-readable negative kind.
    kind: &'static str,
    /// One-line, tool-specific framing of what the empty/negative result means.
    subject: &'static str,
    /// When true, the qualifier is attached even if the collection is non-empty
    /// — e.g. batch reachability, whose `has_references: false` rows are
    /// themselves the negatives an agent must calibrate before deleting.
    always: bool,
    /// Which substrate's completeness gates this tool's absence-trust: embeddings
    /// (`Semantic`) or graph structure (`Structural`). See [`NegativeClass`].
    class: NegativeClass,
}

/// The registry of negative-capable retrieval tools. Returns `None` for any tool
/// that is not retrieval/negative-capable (mutations, session/work/review ops,
/// and tools whose payload is always populated), so no negative is synthesized.
fn spec_for(tool: &str) -> Option<RetrievalSpec> {
    let spec = match tool {
        "semantic_search" => RetrievalSpec {
            field: "results",
            kind: "no_entity_match",
            subject: "no entity declaration matched the search",
            always: false,
            class: NegativeClass::Semantic,
        },
        // Daemon-only: offline returns an error (no payload), so this fires only
        // on the daemon path, where the payload carries `results`.
        "semantic_locate" => RetrievalSpec {
            field: "results",
            kind: "no_ranked_match",
            subject: "no entity ranked above threshold for the query",
            always: false,
            class: NegativeClass::Semantic,
        },
        "find_references" => RetrievalSpec {
            field: "references",
            kind: "no_references",
            subject: "no references to the focal entity were found",
            always: false,
            class: NegativeClass::Structural,
        },
        "graph_neighborhood" => RetrievalSpec {
            field: "entities",
            kind: "no_neighbors",
            subject: "the entity has no graph neighbors at the requested depth",
            always: false,
            class: NegativeClass::Structural,
        },
        "find_dead_code_seeded" => RetrievalSpec {
            field: "candidates",
            kind: "no_seed_match",
            subject: "no entities matched the seed query",
            always: false,
            class: NegativeClass::Structural,
        },
        "trace_data_flow" => RetrievalSpec {
            field: "chain",
            kind: "no_flow",
            subject: "no data-flow chain was found from the focal entity",
            always: false,
            class: NegativeClass::Structural,
        },
        // Bare-array payloads (wrapped under `result` by the annotator).
        "dead_code" => RetrievalSpec {
            field: "",
            kind: "no_dead_code",
            subject: "no unreachable entities were found in the scanned set",
            always: false,
            class: NegativeClass::Structural,
        },
        "entity_history" => RetrievalSpec {
            field: "",
            kind: "no_history",
            subject: "no change history was found for the entity",
            always: false,
            class: NegativeClass::Structural,
        },
        // Batch reachability never returns an empty `results` on success (it
        // errors on empty input), but its `has_references: false` rows ARE the
        // negatives a "safe to delete?" sweep depends on — so always qualify.
        "bulk_check_references" => RetrievalSpec {
            field: "results",
            kind: "reachability_verdicts",
            subject: "per-entity reachability verdicts",
            always: true,
            class: NegativeClass::Structural,
        },
        _ => return None,
    };
    Some(spec)
}

/// Number of items in the tool's result collection within `payload`, or `None`
/// when the expected collection is absent or not an array (in which case no
/// negative is synthesized — we never guess emptiness).
fn collection_len(payload: &Value, field: &str) -> Option<usize> {
    if field.is_empty() {
        payload.as_array().map(Vec::len)
    } else {
        payload.get(field).and_then(Value::as_array).map(Vec::len)
    }
}

/// Render the envelope's embedding coverage as a compact, agent-readable object
/// (with a rounded percentage), or `Value::Null` when coverage is unknown.
fn coverage_value(envelope: &Envelope) -> Value {
    match &envelope.semantic_coverage {
        Some(coverage) => {
            let percent = if coverage.total == 0 {
                100.0
            } else {
                (coverage.indexed as f64 / coverage.total as f64) * 100.0
            };
            json!({
                "indexed": coverage.indexed,
                "total": coverage.total,
                "pending": coverage.pending,
                "complete": coverage.complete,
                "percent": (percent * 10.0).round() / 10.0,
            })
        }
        None => Value::Null,
    }
}

/// A human sentence spelling out "absent as-of X, coverage Y%, degraded Z" and
/// the actionable consequence, so the negative is legible without cross-reading
/// the envelope.
fn build_advice(spec: &RetrievalSpec, envelope: &Envelope, trustworthy: bool) -> String {
    let as_of = match &envelope.graph_as_of {
        Some(value) => format!("graph as-of {value}"),
        None => "an unversioned graph snapshot".to_string(),
    };
    let coverage = match &envelope.semantic_coverage {
        Some(coverage) if coverage.total > 0 => {
            let percent = (coverage.indexed as f64 / coverage.total as f64) * 100.0;
            format!("semantic coverage {percent:.1}%")
        }
        Some(_) => "semantic coverage complete".to_string(),
        None => "semantic coverage unknown".to_string(),
    };
    let degraded = envelope.degraded.active_labels();
    let degraded = if degraded.is_empty() {
        "no degraded signals".to_string()
    } else {
        format!("degraded signals [{}]", degraded.join(", "))
    };

    let consequence = if spec.always {
        if trustworthy {
            "A `has_references: false` row here is an authoritative negative — safe to treat that entity as unreferenced."
        } else {
            "Do NOT treat a `has_references: false` row as proof of disuse: the index is not authoritative yet, so a false verdict may simply mean 'not indexed'. Re-check once trust is authoritative."
        }
    } else if trustworthy {
        "Absence is authoritative: safe to treat the target as genuinely absent/unused."
    } else {
        "Absence is NOT authoritative: do not conclude the target is unused or deletable — an empty result may mean 'not indexed'. Re-check after embedding is complete and the daemon is healthy."
    };

    format!(
        "{}, against {as_of} with {coverage} and {degraded}. {consequence}",
        spec.subject
    )
}

/// True when `payload.focal_entity.kind` is a method — the entity kind whose
/// incoming call edges the linker under-resolves (FIR-938), so absence of
/// references must not be certified as authoritative.
fn focal_entity_is_method(payload: &Value) -> bool {
    payload
        .get("focal_entity")
        .and_then(|focal| focal.get("kind"))
        .and_then(|kind| kind.as_str())
        .is_some_and(|kind| kind.eq_ignore_ascii_case("method"))
}

/// Build a confidence-qualified negative for `tool`'s `payload`, enriched from
/// `envelope`, or `None` when the tool is not negative-capable or it returned a
/// non-empty result (and is not an `always`-qualify tool).
///
/// The returned object is additive: callers attach it under [`NEGATIVE_KEY`]
/// beside the existing payload keys, never replacing them.
pub fn negative_for(tool: &str, payload: &Value, envelope: &Envelope) -> Option<Value> {
    let spec = spec_for(tool)?;
    let count = collection_len(payload, spec.field)?;
    if count != 0 && !spec.always {
        return None;
    }

    let (mut trustworthy, mut trust_reason) = envelope.negative_trust(spec.class);

    // FIR-938: receiver-method calls (`x.method()`) are resolved by bare name in
    // the linker while method entities are keyed by their qualified name, so a
    // method's incoming `Calls` edges are frequently dropped. An empty
    // `find_references` for a method is therefore NOT an authoritative "unused"
    // verdict — the calls may simply never have been linked. Never let an agent
    // read "safe to delete" off an incomplete call graph: downgrade to
    // inconclusive so the absence is flagged as possibly-unresolved, not certain.
    if tool == "find_references" && focal_entity_is_method(payload) {
        trustworthy = false;
        trust_reason = "method_call_resolution_incomplete: receiver-method calls are \
             linked by bare name and may be unresolved, so an empty result is not an \
             authoritative absence for a method";
    }

    let interpretation = if spec.always {
        "qualified_verdicts"
    } else {
        "absent_as_indexed"
    };

    let mut negative = Map::new();
    negative.insert("kind".to_string(), json!(spec.kind));
    negative.insert("subject".to_string(), json!(spec.subject));
    negative.insert("result_count".to_string(), json!(count));
    negative.insert("interpretation".to_string(), json!(interpretation));
    negative.insert("safe_to_conclude_absent".to_string(), json!(trustworthy));
    negative.insert(
        "trust".to_string(),
        json!(if trustworthy {
            "authoritative"
        } else {
            "inconclusive"
        }),
    );
    negative.insert("trust_reason".to_string(), json!(trust_reason));
    negative.insert(
        "graph_as_of".to_string(),
        envelope.graph_as_of.clone().unwrap_or(Value::Null),
    );
    negative.insert("semantic_coverage".to_string(), coverage_value(envelope));
    negative.insert(
        "degraded_signals".to_string(),
        json!(envelope.degraded.active_labels()),
    );
    negative.insert(
        "advice".to_string(),
        json!(build_advice(&spec, envelope, trustworthy)),
    );
    Some(Value::Object(negative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Degraded, Envelope, SemanticCoverage};

    /// A daemon envelope whose SEMANTIC substrate is complete — full embedding
    /// coverage, no degraded signals: the only state in which a *semantic* tool's
    /// absent result is authoritative.
    fn semantic_authoritative_envelope() -> Envelope {
        let mut env = Envelope::daemon();
        env.semantic_coverage = Some(SemanticCoverage {
            indexed: 100,
            total: 100,
            pending: 0,
            complete: true,
            note: None,
        });
        env.graph_as_of = Some(json!("change:deadbeef"));
        env
    }

    /// A daemon envelope whose GRAPH substrate is complete — initialized + loaded
    /// (folded honestly from `/health`), no degraded signals, and crucially NO
    /// embedding coverage reported. *Structural* tools are authoritative here;
    /// semantic tools are not (they still need coverage).
    fn structural_ready_envelope() -> Envelope {
        Envelope::daemon().with_health(&json!({
            "graph_loaded": true,
            "initialized": true,
            "graph_generation": 12,
        }))
    }

    #[test]
    fn non_retrieval_tool_gets_no_negative() {
        let payload = json!({ "ok": true });
        assert!(negative_for("kin_work_create", &payload, &Envelope::daemon()).is_none());
    }

    #[test]
    fn non_empty_result_gets_no_negative() {
        let payload = json!({ "results": [{ "id": "x" }] });
        assert!(negative_for("semantic_search", &payload, &Envelope::daemon()).is_none());
    }

    #[test]
    fn missing_collection_field_yields_no_negative() {
        // Honesty: if the expected field is absent, we cannot tell it was empty.
        let payload = json!({ "unexpected": 1 });
        assert!(negative_for("semantic_search", &payload, &Envelope::daemon()).is_none());
    }

    #[test]
    fn empty_search_offline_is_inconclusive() {
        let payload = json!({ "query": "auth", "results": [] });
        let negative = negative_for("semantic_search", &payload, &Envelope::offline())
            .expect("empty retrieval yields a negative");
        assert_eq!(negative["kind"], json!("no_entity_match"));
        assert_eq!(negative["result_count"], json!(0));
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("offline_fallback"));
        // Offline observes no coverage/freshness — honest nulls, not fabricated.
        assert_eq!(negative["graph_as_of"], Value::Null);
        assert_eq!(negative["semantic_coverage"], Value::Null);
    }

    // ---- semantic class: absence gated on EMBEDDING coverage ----

    #[test]
    fn semantic_search_complete_coverage_is_authoritative() {
        let payload = json!({ "results": [] });
        let negative = negative_for(
            "semantic_search",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("semantic_authoritative"));
        assert_eq!(negative["semantic_coverage"]["percent"], json!(100.0));
    }

    #[test]
    fn semantic_search_partial_coverage_is_inconclusive() {
        let mut env = Envelope::daemon();
        env.semantic_coverage = Some(SemanticCoverage {
            indexed: 40,
            total: 100,
            pending: 60,
            complete: false,
            note: Some("indexing".to_string()),
        });
        let payload = json!({ "results": [] });
        let negative = negative_for("semantic_search", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("coverage_partial"));
        assert_eq!(negative["semantic_coverage"]["percent"], json!(40.0));
    }

    #[test]
    fn semantic_search_coverage_unknown_even_on_ready_graph_is_inconclusive() {
        // The class boundary: a fully initialized + loaded graph does NOT make a
        // semantic absence authoritative — embeddings can still be incomplete, so
        // an empty semantic result may mean "not indexed".
        let payload = json!({ "results": [] });
        let negative =
            negative_for("semantic_search", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("coverage_unknown"));
    }

    // ---- structural class: absence gated on GRAPH initialized + loaded ----

    #[test]
    fn find_references_on_loaded_graph_is_authoritative_without_coverage() {
        // The headline structural lift: an empty find_references is authoritative
        // on an initialized + loaded graph even with NO embedding coverage —
        // structural tools read typed relations, not embeddings.
        let payload = json!({ "total_upstream": 0, "references": [] });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["kind"], json!("no_references"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("structural_authoritative"));
        // graph_as_of was lifted from the /health generation marker.
        assert_eq!(negative["graph_as_of"], json!({ "generation": 12 }));
        // No embedding coverage observed — honest null, not fabricated.
        assert_eq!(negative["semantic_coverage"], Value::Null);
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("authoritative"));
    }

    #[test]
    fn find_references_on_method_is_inconclusive_despite_loaded_graph() {
        // FIR-938: receiver-method call edges are under-resolved by the linker
        // (method entities are keyed by qualified name; calls arrive bare), so an
        // empty find_references for a method must NOT be certified authoritative
        // ("safe to delete") even on a healthy, loaded graph.
        let payload = json!({
            "focal_entity": { "kind": "method", "name": "Foo::bar" },
            "references": []
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("method_call_resolution_incomplete"));
    }

    #[test]
    fn find_references_on_function_stays_authoritative() {
        // The gate is method-specific: a free function's incoming call edges
        // resolve, so its empty find_references remains an authoritative absence.
        let payload = json!({
            "focal_entity": { "kind": "function", "name": "free_fn" },
            "references": []
        });
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
    }

    #[test]
    fn find_references_graph_uninitialized_is_inconclusive() {
        // graph_loaded but first reconciliation not confirmed: a structural
        // absence is not authoritative, and the reason names the GRAPH gate — not
        // coverage (find_references does not depend on embeddings).
        let env = Envelope::daemon().with_health(&json!({
            "reconciliation_status": "reconciling",
            "graph_loaded": true,
        }));
        let payload = json!({ "references": [] });
        let negative = negative_for("find_references", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("graph_uninitialized"));
    }

    #[test]
    fn find_references_degraded_is_inconclusive() {
        // The degraded gate is class-independent: it short-circuits before the
        // structural graph check.
        let mut env = structural_ready_envelope();
        env.degraded = Degraded {
            embed_worker_failed: Some(true),
            ..Degraded::default()
        };
        let payload = json!({ "references": [] });
        let negative = negative_for("find_references", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("degraded"));
        assert_eq!(negative["degraded_signals"], json!(["embed_worker_failed"]));
    }

    #[test]
    fn bare_array_dead_code_empty_yields_negative() {
        // dead_code returns a bare array; empty means "nothing dead" but its
        // completeness still hinges on coverage/freshness.
        let payload = json!([]);
        let negative = negative_for("dead_code", &payload, &Envelope::offline()).unwrap();
        assert_eq!(negative["kind"], json!("no_dead_code"));
        assert_eq!(negative["result_count"], json!(0));
    }

    #[test]
    fn bare_array_entity_history_nonempty_yields_no_negative() {
        let payload = json!([{ "change_id": "c1" }]);
        assert!(negative_for("entity_history", &payload, &Envelope::daemon()).is_none());
    }

    #[test]
    fn bulk_check_always_qualifies_even_when_populated() {
        let payload = json!({
            "results": [
                { "entity_id": "a", "has_references": false },
                { "entity_id": "b", "has_references": true },
            ]
        });
        let negative = negative_for("bulk_check_references", &payload, &Envelope::offline())
            .expect("bulk always qualifies");
        assert_eq!(negative["kind"], json!("reachability_verdicts"));
        assert_eq!(negative["interpretation"], json!("qualified_verdicts"));
        assert_eq!(negative["result_count"], json!(2));
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("has_references: false"));
    }

    #[test]
    fn dead_code_on_loaded_graph_is_authoritative() {
        // dead_code is structural and returns a bare array: an empty result is
        // authoritative on an initialized + loaded graph, regardless of embedding
        // coverage. Mirrors find_references through a different payload shape.
        let payload = json!([]);
        let negative = negative_for("dead_code", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["kind"], json!("no_dead_code"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("structural_authoritative"));
    }
}
