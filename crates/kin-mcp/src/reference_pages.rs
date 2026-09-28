// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Frozen, lossless reference pages using the semantic-record page transport.

use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Value};

pub use crate::trace_pages::Context;

pub fn context(arguments: &HashMap<String, Value>, authority: &Value) -> Context {
    // Excluding only transport controls binds every answer-shaping argument,
    // including filters, snippets and the answer-only projection. Unknown
    // arguments cannot silently gain semantics partway through a continuation.
    let query: BTreeMap<_, _> = arguments
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "cursor" | "max_chars" | "max_response_chars"))
        .collect();
    Context::new(
        &json!({"tool": "find_references", "arguments": query}),
        authority,
    )
}

pub fn resume(cursor: &str, context: &Context, max_bytes: usize) -> Result<Value, String> {
    crate::trace_pages::resume(cursor, context, max_bytes)
        .map_err(|error| error.replace("trace", "reference"))
}

pub fn finalize(
    result: crate::ToolCallResult,
    envelope: crate::Envelope,
    context: Context,
    budget: &crate::budget::ResponseBudget,
) -> crate::ToolCallResult {
    crate::trace_pages::finalize_kind(
        result,
        envelope,
        context,
        budget.max_chars,
        crate::trace_pages::PageKind::References,
        budget.answer_only,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> HashMap<String, Value> {
        HashMap::from([("query".into(), json!("Adapter.send"))])
    }

    #[test]
    fn reference_pages_preserve_all_callers_and_reject_query_or_authority_changes() {
        let arguments = query();
        let authority = json!({"repo":"example", "truth":4, "source":"committed", "session":"a"});
        let current = context(&arguments, &authority);
        let rows: Vec<_> = (0..80).map(|index| json!({
            "entity_id": format!("00000000-0000-4000-8000-{index:012}"),
            "name":format!("caller_{index}"), "sites":[{"callee":"adapter.send", "line_in_entity":index}],
            "resolution":"type_resolved", "signature":"x".repeat(150),
        })).collect();
        let original = json!({
            "references": rows, "total_upstream": 80,
            "call_sites":{"candidate_count":3,"candidates":[{"caller":"a"},{"caller":"b"},{"caller":"c"}],"clauses":["unresolved binding"]},
            "negative":{"safe_to_conclude_absent":false},
            "target_ambiguity":{"candidates":[]},
            "_kin":{"verdict":{"state":"inconclusive"},
                "repository":{"root":"/example/project"},
                "graph_as_of":{"generation":4,"graph_root":"captured-root"}},
        });
        let mut page = crate::trace_pages::start_kind(
            original.clone(),
            current.clone(),
            4000,
            crate::trace_pages::PageKind::References,
        )
        .unwrap();
        let first_cursor = page["next_cursor"].as_str().unwrap().to_string();
        let mut seen = Vec::new();
        let mut candidates = Vec::new();
        let mut readings = serde_json::Map::new();
        let mut pages = 0;
        loop {
            pages += 1;
            assert!(pages < 100);
            assert!(serde_json::to_vec(&page).unwrap().len() <= 4000);
            assert_eq!(page["negative"]["safe_to_conclude_absent"], false);
            for key in ["repository", "graph_as_of"] {
                assert_eq!(page["_kin"][key], original["_kin"][key]);
            }
            seen.extend(page["references"].as_array().unwrap().iter().cloned());
            candidates.extend(
                page.pointer("/call_sites/candidates")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
            for reading in page["readings"].as_array().into_iter().flatten() {
                readings.insert(
                    reading["key"].as_str().unwrap().into(),
                    reading["value"].clone(),
                );
            }
            let Some(cursor) = page["next_cursor"].as_str() else {
                break;
            };
            page = resume(cursor, &current, 4000).unwrap();
        }
        assert_eq!(seen, rows);
        assert_eq!(
            candidates,
            original["call_sites"]["candidates"]
                .as_array()
                .unwrap()
                .clone()
        );
        let mut reconstructed = Value::Object(readings);
        reconstructed["references"] = json!(seen);
        reconstructed["call_sites"]["candidates"] = json!(candidates);
        assert_eq!(reconstructed, original);
        for (key, value) in [
            ("query", json!("Other.send")),
            ("relation_kinds", json!(["calls"])),
            ("include_snippets", json!(true)),
            ("min_resolution", json!("name_only")),
            ("answer_only", json!(true)),
        ] {
            let mut changed = arguments.clone();
            changed.insert(key.into(), value);
            assert!(resume(&first_cursor, &context(&changed, &authority), 4000)
                .unwrap_err()
                .contains("query changed"));
        }
        assert!(resume(
            &first_cursor,
            &context(&arguments, &json!({"repo":"other"})),
            4000
        )
        .unwrap_err()
        .contains("authority scope changed"));
        let mut resized = arguments;
        resized.insert("max_chars".into(), json!(6000));
        resized.insert("cursor".into(), json!(&first_cursor));
        assert!(resume(&first_cursor, &context(&resized, &authority), 6000).is_ok());
    }
}
