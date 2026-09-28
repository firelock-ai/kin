// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::{json, Value};

/// Inspect the actual wire page before making its semantic records available
/// to the existing truth graders. Reassembly never substitutes for raw checks.
#[derive(Default)]
pub(crate) struct TraceAssembly {
    value: serde_json::Map<String, Value>,
    rows: std::collections::BTreeMap<String, Vec<Value>>,
    fields: std::collections::BTreeMap<(String, usize), serde_json::Map<String, Value>>,
    fragments: std::collections::BTreeMap<(String, usize, Option<String>), String>,
}

impl TraceAssembly {
    fn record(&mut self, collection: &str, key: Option<&str>, value: Value) {
        if collection == "readings" {
            assert!(self.value.insert(key.unwrap().to_string(), value).is_none());
        } else {
            self.rows
                .entry(collection.to_string())
                .or_default()
                .push(value);
        }
    }

    pub(crate) fn add(&mut self, page: &Value, wire: &str, ceiling: usize) {
        assert!(
            wire.len() <= ceiling,
            "{} bytes exceed {ceiling}",
            wire.len()
        );
        assert_eq!(page["_kin"]["response"]["chars_after_budget"], wire.len());
        assert_eq!(page["_kin"]["response"]["max_chars"], ceiling);
        assert_eq!(page["negative"]["safe_to_conclude_absent"], false);
        assert_eq!(page["_kin"]["verdict"]["safe_to_conclude_absent"], false);
        for collection in [
            "chain",
            "candidates",
            "more_candidates",
            "target_candidates",
        ] {
            for row in page[collection].as_array().into_iter().flatten() {
                self.record(collection, None, row.clone());
            }
        }
        for reading in page["readings"].as_array().into_iter().flatten() {
            self.record(
                "readings",
                reading["key"].as_str(),
                reading["value"].clone(),
            );
        }
        if let Some(fragment) = page.get("record_fragment") {
            let collection = fragment["collection"].as_str().unwrap();
            let index = fragment["index"].as_u64().unwrap() as usize;
            let field = fragment["field"].as_str().map(str::to_string);
            let key = (collection.to_string(), index, field.clone());
            let text = self.fragments.entry(key.clone()).or_default();
            assert_eq!(
                text.len(),
                fragment["byte_offset"].as_u64().unwrap() as usize
            );
            text.push_str(fragment["text"].as_str().unwrap());
            if fragment["field_complete"] == true {
                assert_eq!(
                    text.len(),
                    fragment["total_bytes"].as_u64().unwrap() as usize
                );
                let value = if fragment["encoding"] == "utf8" {
                    json!(text)
                } else {
                    serde_json::from_str(text).unwrap()
                };
                self.fragments.remove(&key);
                let value = if let Some(field) = field {
                    let record_key = (collection.to_string(), index);
                    let record = self.fields.entry(record_key.clone()).or_default();
                    assert!(record.insert(field, value).is_none());
                    (fragment["record_complete"] == true)
                        .then(|| Value::Object(self.fields.remove(&record_key).unwrap()))
                } else {
                    Some(value)
                };
                if let Some(value) = value {
                    self.record(collection, fragment["key"].as_str(), value);
                }
            }
        }
    }

    pub(crate) fn finish(mut self) -> Value {
        assert!(self.fragments.is_empty() && self.fields.is_empty());
        let target = self.rows.remove("target_candidates");
        for (key, rows) in self.rows {
            self.value.insert(key, json!(rows));
        }
        self.value.entry("chain".to_string()).or_insert(json!([]));
        let mut value = Value::Object(self.value);
        if let Some(target) = target {
            value["target_ambiguity"]["candidates"] = json!(target);
        }
        value
    }
}
