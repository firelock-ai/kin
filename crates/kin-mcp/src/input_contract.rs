// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Argument rules a served tool schema cannot carry, checked by the server.
//!
//! A tool's `inputSchema` used to say "at least one of these fields" with a
//! top-level `anyOf`, and `kin_mutate` said "a keyed call names its session"
//! with a top-level `allOf` holding an `if`/`then`. Model provider tool APIs
//! refuse a schema whose top level is a combinator, and a client that loads
//! tools for one of them drops such a tool without a word: Claude Code listed
//! 19 of the 22 tools `agent-default` served, missing `semantic_locate`,
//! `get_context_pack` and `lexical_lookup`, while Kin's own instructions sent
//! the model to `semantic_locate` first.
//!
//! So every served schema is a plain `type: object` with its properties, one
//! schema for every client, and the rules the combinators carried live here:
//!
//! * [`alternatives`] is each tool's "at least one of" rule, the `required`
//!   sets of the `anyOf` it replaced. [`refusal`] enforces it on every named
//!   call before anything runs, and the routed tool reads the same table, so a
//!   routed refusal and a named one say the same thing.
//! * The keyed `kin_mutate` rule, a `request_id` needing a `session_id`, only
//!   `scope: repository` and only the durable fields, is enforced where it
//!   always was: the MCP mutate adapter refuses a keyed call with no session,
//!   and the daemon's durable route refuses any other field or scope.
//!
//! A field counts as supplied when it is present and not null, which is how
//! the routed tool always read these rules. None of the properties involved
//! accepts null, so a null the old schema refused by type is still refused.
//! Which field wins when several are supplied is the handler's business and is
//! unchanged: this checks that one is there, never which one is used.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::types::ToolCallResult;

/// One tool's "at least one of" rule: the call must supply every field of at
/// least one set.
struct Alternatives {
    tool: &'static str,
    sets: &'static [&'static [&'static str]],
    /// One call that works, as JSON text of the tool's arguments.
    example: &'static str,
}

const ALTERNATIVES: &[Alternatives] = &[
    Alternatives {
        tool: "semantic_locate",
        sets: &[&["query"], &["cursor"]],
        example: r#"{"query":"where failed requests are retried"}"#,
    },
    Alternatives {
        tool: "get_context_pack",
        sets: &[&["entity_id"], &["entities"], &["question"]],
        example: r#"{"question":"how are failed requests retried"}"#,
    },
    Alternatives {
        tool: crate::handlers::lexical::TOOL_NAME,
        sets: &[&["literal"], &["cursor"]],
        example: r#"{"literal":"retry_after"}"#,
    },
    Alternatives {
        tool: "kin_review_create",
        sets: &[
            &["base", "head"],
            &["scope_type", "entity_ids"],
            &["scopes"],
        ],
        example: r#"{"title":"Review the retry change","base":"<base change id>","head":"<head change id>"}"#,
    },
    Alternatives {
        tool: "kin_review_assign",
        sets: &[&["reviewer"], &["reviewers"]],
        example: r#"{"review_id":"<review id>","reviewer":"reviewer@example.com"}"#,
    },
];

/// `tool`'s "at least one of" rule: the field sets of which a call must supply
/// one in full. Empty for a tool with no such rule.
pub fn alternatives(tool: &str) -> &'static [&'static [&'static str]] {
    ALTERNATIVES
        .iter()
        .find(|rule| rule.tool == tool)
        .map_or(&[], |rule| rule.sets)
}

/// Every tool with an "at least one of" rule.
pub fn tools_with_alternatives() -> impl Iterator<Item = &'static str> {
    ALTERNATIVES.iter().map(|rule| rule.tool)
}

/// Whether `arguments` supply `field`: present and not null.
pub fn supplied(arguments: &HashMap<String, Value>, field: &str) -> bool {
    arguments.get(field).is_some_and(|value| !value.is_null())
}

/// Whether `arguments` satisfy `tool`'s "at least one of" rule, if it has one.
pub fn satisfies_alternatives(tool: &str, arguments: &HashMap<String, Value>) -> bool {
    let sets = alternatives(tool);
    sets.is_empty()
        || sets
            .iter()
            .any(|set| set.iter().all(|field| supplied(arguments, field)))
}

/// The rule in words: `query or cursor`, `base and head or scopes`.
pub fn spell(sets: &[&[&str]]) -> String {
    sets.iter()
        .map(|set| set.join(" and "))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// The refusal a named call gets when it breaks `tool`'s "at least one of"
/// rule, or `None` when it keeps it. Structured the way a named refusal is:
/// what is missing, and one call that works.
pub fn refusal(tool: &str, arguments: &HashMap<String, Value>) -> Option<ToolCallResult> {
    let rule = ALTERNATIVES.iter().find(|rule| rule.tool == tool)?;
    if satisfies_alternatives(tool, arguments) {
        return None;
    }
    let example: Value = serde_json::from_str(rule.example).unwrap_or_else(|_| json!({}));
    let value = json!({
        "error": "missing_arguments",
        "message": format!(
            "{tool} needs {}, and this call supplied none of them, so nothing ran.",
            spell(rule.sets)
        ),
        "needs_one_of": rule.sets,
        "example": {"name": tool, "arguments": example},
    });
    Some(ToolCallResult::error(
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
    ))
}

/// The JSON-schema keywords a provider tool API refuses at a schema's top
/// level.
pub const TOP_LEVEL_COMBINATORS: [&str; 7] =
    ["oneOf", "anyOf", "allOf", "not", "if", "then", "else"];

/// The combinators at the top of `schema`, which no served schema may carry.
pub fn top_level_combinators(schema: &Value) -> Vec<&'static str> {
    TOP_LEVEL_COMBINATORS
        .into_iter()
        .filter(|keyword| schema.get(*keyword).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(value: Value) -> HashMap<String, Value> {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn every_example_keeps_its_own_rule() {
        for rule in ALTERNATIVES {
            let example: HashMap<String, Value> = serde_json::from_str(rule.example).unwrap();
            assert!(
                satisfies_alternatives(rule.tool, &example),
                "{}'s example breaks its rule: {}",
                rule.tool,
                rule.example
            );
            let registered = crate::tools::tool_definitions();
            let schema = &registered
                .tools
                .iter()
                .find(|tool| tool.name == rule.tool)
                .unwrap_or_else(|| panic!("{} is not registered", rule.tool))
                .input_schema;
            for field in rule.sets.iter().flat_map(|set| set.iter()) {
                assert!(
                    schema["properties"].get(*field).is_some(),
                    "{}'s rule names {field}, which its schema does not define",
                    rule.tool
                );
            }
            for field in example.keys() {
                assert!(
                    schema["properties"].get(field).is_some(),
                    "{}'s example passes {field}, which its schema does not define",
                    rule.tool
                );
            }
        }
    }

    /// The five schemas as served at cf32b66b3, reduced to what a validator
    /// reads for these rules: `type`, `required`, each property's `type`, and
    /// the top-level combinator. `kin_mutate` rides along for the record; its
    /// keyed rule is proved where it is enforced.
    const BEFORE: &str = include_str!("testdata/combinator_schemas_cf32b66b3.json");

    /// A JSON-schema validator for exactly the keywords the old schemas used.
    /// Anything else in a schema is a failure of this test, not a pass.
    fn valid(schema: &Value, instance: &Value) -> bool {
        let object = schema.as_object().expect("a schema is an object");
        for (keyword, rule) in object {
            let ok = match keyword.as_str() {
                "type" => match rule.as_str().unwrap() {
                    "object" => instance.is_object(),
                    "string" => instance.is_string(),
                    "array" => instance.is_array(),
                    "integer" => instance.is_i64() || instance.is_u64(),
                    "boolean" => instance.is_boolean(),
                    other => panic!("unexpected type {other}"),
                },
                "required" => rule
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|name| instance.get(name.as_str().unwrap()).is_some()),
                "properties" => rule.as_object().unwrap().iter().all(|(name, property)| {
                    instance
                        .get(name)
                        .is_none_or(|value| valid(property, value))
                }),
                "anyOf" => rule
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|branch| valid(branch, instance)),
                "allOf" => rule
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|branch| valid(branch, instance)),
                "if" => {
                    let then = object.get("then").cloned().unwrap_or(json!({}));
                    !valid(rule, instance) || valid(&then, instance)
                }
                "then" => true,
                "const" => instance == rule,
                "propertyNames" => instance
                    .as_object()
                    .is_none_or(|fields| fields.keys().all(|name| valid(rule, &json!(name)))),
                "enum" => rule.as_array().unwrap().contains(instance),
                other => panic!("the evaluator does not read {other}"),
            };
            if !ok {
                return false;
            }
        }
        true
    }

    /// The old schema without its top-level combinators: what is served now.
    fn flattened(schema: &Value) -> Value {
        let mut flat = schema.clone();
        let object = flat.as_object_mut().unwrap();
        for keyword in TOP_LEVEL_COMBINATORS {
            object.remove(keyword);
        }
        flat
    }

    /// Every input over each rule's fields, each absent, a well-typed value or
    /// null, alone and beside an unrelated field and the tool's other required
    /// fields, is accepted by the served schema and the server's rule exactly
    /// when the old schema accepted it.
    #[test]
    fn the_server_rule_accepts_exactly_what_the_old_schema_accepted() {
        let before: std::collections::BTreeMap<String, Value> =
            serde_json::from_str(BEFORE).unwrap();
        let mut graded = 0usize;
        for tool in tools_with_alternatives() {
            let old = &before[tool];
            assert!(
                old.get("anyOf").is_some(),
                "{tool} carried no anyOf at cf32b66b3"
            );
            let now = crate::tools::tool_definitions()
                .tools
                .into_iter()
                .find(|candidate| candidate.name == tool)
                .unwrap()
                .input_schema;
            assert!(
                top_level_combinators(&now).is_empty(),
                "{tool} still serves a combinator"
            );
            let fields: Vec<&str> = {
                let mut fields: Vec<&str> = alternatives(tool)
                    .iter()
                    .flat_map(|set| set.iter().copied())
                    .collect();
                fields.sort_unstable();
                fields.dedup();
                fields
            };
            let typed = |field: &str| match old["properties"][field]["type"].as_str() {
                Some("array") => json!(["x"]),
                Some("string") => json!("x"),
                other => panic!("{tool}.{field} has type {other:?}"),
            };
            // Each field takes one of three states: absent, typed, null.
            for mask in 0..3usize.pow(fields.len() as u32) {
                let mut code = mask;
                let mut instance = serde_json::Map::new();
                for field in &fields {
                    match code % 3 {
                        0 => {}
                        1 => {
                            instance.insert(field.to_string(), typed(field));
                        }
                        _ => {
                            instance.insert(field.to_string(), Value::Null);
                        }
                    }
                    code /= 3;
                }
                for extra in [false, true] {
                    let mut instance = instance.clone();
                    for required in old["required"].as_array().into_iter().flatten() {
                        let name = required.as_str().unwrap();
                        instance.insert(name.to_string(), json!("x"));
                    }
                    if extra {
                        instance.insert("limit".to_string(), json!(3));
                    }
                    let instance = Value::Object(instance);
                    let arguments: HashMap<String, Value> =
                        serde_json::from_value(instance.clone()).unwrap();
                    let was = valid(old, &instance);
                    let is =
                        valid(&flattened(old), &instance) && refusal(tool, &arguments).is_none();
                    assert_eq!(was, is, "{tool} {instance}: before {was}, now {is}");
                    graded += 1;
                }
            }
        }
        assert!(graded >= 200, "graded only {graded} inputs");
    }

    /// No tool on any profile serves a schema that opens with a combinator.
    /// Each profile's listing is built by the function `tools/list` writes it
    /// with. `kin-cli` holds the same over every profile token it accepts.
    #[test]
    fn no_profile_serves_a_top_level_combinator() {
        let names = |list: &'static [&'static str]| Some(crate::tools::name_set(list));
        let profiles: Vec<(&str, crate::server::McpServerConfig)> = vec![
            (
                "agent-default",
                crate::tools::agent_default_tool_names(),
                true,
                false,
            ),
            (
                "agent-query",
                crate::tools::agent_query_tool_names(),
                true,
                true,
            ),
            (
                "agent-search",
                crate::tools::agent_search_tool_names(),
                true,
                true,
            ),
            (
                "benchmark",
                crate::tools::benchmark_tool_names(),
                false,
                false,
            ),
            (
                "context-bench",
                crate::tools::context_bench_tool_names(),
                false,
                false,
            ),
        ]
        .into_iter()
        .map(|(profile, list, belt, numbered)| {
            (
                profile,
                crate::server::McpServerConfig {
                    allowed_tools: names(list),
                    agent_belt: belt,
                    number_entity_lines: numbered,
                    ..Default::default()
                },
            )
        })
        .chain([
            ("full", crate::server::McpServerConfig::default()),
            (
                "agent-routed",
                crate::server::McpServerConfig {
                    routed: Some(crate::routed::RoutedSurface::WITH_WRITES),
                    ..Default::default()
                },
            ),
            (
                "agent-routed-query",
                crate::server::McpServerConfig {
                    routed: Some(crate::routed::RoutedSurface::READ_ONLY),
                    ..Default::default()
                },
            ),
        ])
        .collect();
        let mut served = 0usize;
        let mut offenders = Vec::new();
        for (profile, config) in &profiles {
            for tool in crate::server::served_tools_for(config).tools {
                served += 1;
                let found = top_level_combinators(&tool.input_schema);
                if !found.is_empty() || tool.input_schema["type"] != "object" {
                    offenders.push(format!("{profile}/{}: {found:?}", tool.name));
                }
            }
        }
        assert!(offenders.is_empty(), "{offenders:#?}");
        assert!(served > 100, "the sweep served only {served} tools");
    }

    #[test]
    fn a_refusal_names_what_is_missing_and_one_call_that_works() {
        let refused = refusal("semantic_locate", &args(json!({"limit": 5}))).unwrap();
        assert_eq!(refused.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = &refused.content[0];
        let answer: Value = serde_json::from_str(text).unwrap();
        assert!(answer["message"]
            .as_str()
            .unwrap()
            .contains("needs query or cursor"));
        assert_eq!(answer["example"]["name"], "semantic_locate");
        assert_eq!(
            answer["example"]["arguments"]["query"],
            "where failed requests are retried"
        );
        assert!(refusal("semantic_locate", &args(json!({"cursor": "c"}))).is_none());
        // A null field supplies nothing.
        assert!(refusal("semantic_locate", &args(json!({"query": null}))).is_some());
        // A tool with no rule is never refused here.
        assert!(refusal("trace_path", &args(json!({}))).is_none());
        assert_eq!(
            spell(alternatives("kin_review_create")),
            "base and head or scope_type and entity_ids or scopes"
        );
    }
}
