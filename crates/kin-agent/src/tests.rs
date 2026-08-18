// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Unit tests for the parsers, the router, the envelope reading and path safety.

use crate::belt::{self, Belt, LocalTool, Route};
use crate::mcp::unwrap_tool_result;
use crate::parse::{self, CallShape, Turn};
use serde_json::json;
use std::collections::BTreeSet;

fn belt_names() -> BTreeSet<String> {
    ["mcp__kin__semantic_locate", "edit_file", "write_file"]
        .into_iter()
        .map(ToString::to_string)
        .collect()
}

#[test]
fn native_tool_calls_are_read() {
    let choice = json!({
        "message": {
            "role": "assistant",
            "content": "Looking that up.",
            "tool_calls": [{
                "id": "call_abc",
                "type": "function",
                "function": {
                    "name": "mcp__kin__semantic_locate",
                    "arguments": "{\"query\": \"where is parse_choice\"}"
                }
            }]
        },
        "finish_reason": "tool_calls"
    });
    let Turn::ToolCalls { text, calls } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected tool calls");
    };
    assert_eq!(text, "Looking that up.");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name, "mcp__kin__semantic_locate");
    assert_eq!(calls[0].shape, CallShape::Native);
    assert_eq!(calls[0].arguments["query"], "where is parse_choice");
}

#[test]
fn qwen_text_shaped_tool_calls_are_read() {
    // Qwen answers in prose with the call marked up rather than filling tool_calls.
    let choice = json!({
        "message": {
            "role": "assistant",
            "content": "I will search.\n<tool_call>\n<function=mcp__kin__semantic_locate>\n<parameter=query>\nauthentication middleware\n</parameter>\n<parameter=limit>\n5\n</parameter>\n</function>\n</tool_call>"
        },
        "finish_reason": "stop"
    });
    let Turn::ToolCalls { text, calls } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected tool calls");
    };
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].shape, CallShape::QwenText);
    assert_eq!(calls[0].arguments["query"], "authentication middleware");
    // A bare number in a parameter block becomes a number, not the string "5".
    assert_eq!(calls[0].arguments["limit"], 5);
    // The markup is stripped out of the prose the transcript records.
    assert_eq!(text, "I will search.");
}

#[test]
fn gemma_text_shaped_tool_calls_are_read() {
    let choice = json!({
        "message": {
            "role": "assistant",
            "content": "<|tool_call>call: mcp__kin__semantic_locate{\"query\": \"token refresh\"}<tool_call|>"
        },
        "finish_reason": "stop"
    });
    let Turn::ToolCalls { calls, .. } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected tool calls");
    };
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].shape, CallShape::GemmaText);
    assert_eq!(calls[0].arguments["query"], "token refresh");
}

#[test]
fn gemma_special_quote_tokens_are_normalized() {
    let choice = json!({
        "message": {
            "role": "assistant",
            "content": "<|tool_call>call: functions.mcp__kin__semantic_locate{<|\"|>query<|\"|>: <|\"|>retry backoff<|\"|>}<tool_call|>"
        }
    });
    let Turn::ToolCalls { calls, .. } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected tool calls");
    };
    assert_eq!(calls[0].name, "mcp__kin__semantic_locate");
    assert_eq!(calls[0].arguments["query"], "retry backoff");
}

#[test]
fn json_text_shaped_tool_calls_are_read() {
    let choice = json!({
        "message": {
            "role": "assistant",
            "content": "<tool_call>{\"name\": \"mcp__kin__semantic_locate\", \"arguments\": {\"query\": \"cache eviction\"}}</tool_call>"
        }
    });
    let Turn::ToolCalls { calls, .. } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected tool calls");
    };
    assert_eq!(calls[0].shape, CallShape::JsonText);
    assert_eq!(calls[0].arguments["query"], "cache eviction");
}

#[test]
fn a_text_shaped_call_for_an_unknown_tool_is_not_minted() {
    // Prose that merely mentions a tool must not become a call, which is why the text
    // readers only recognize names that are actually in the belt.
    let choice = json!({
        "message": {
            "role": "assistant",
            "content": "<tool_call><function=run_shell><parameter=cmd>ls</parameter></function></tool_call>"
        }
    });
    let turn = parse::parse_choice(&choice, &belt_names());
    assert!(
        !matches!(turn, Turn::ToolCalls { .. }),
        "an off-belt name must not become a call: {turn:?}"
    );
}

#[test]
fn plain_prose_is_a_final_answer() {
    let choice = json!({
        "message": { "role": "assistant", "content": "The parser lives in parse.rs." },
        "finish_reason": "stop"
    });
    assert_eq!(
        parse::parse_choice(&choice, &belt_names()),
        Turn::Final {
            text: "The parser lives in parse.rs.".into()
        }
    );
}

#[test]
fn an_empty_turn_is_unusable_and_says_why() {
    let choice =
        json!({ "message": { "role": "assistant", "content": "" }, "finish_reason": "stop" });
    let Turn::Unusable { reason, .. } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected unusable");
    };
    assert!(reason.contains("no content"), "reason was: {reason}");
}

#[test]
fn a_truncated_turn_is_unusable_and_says_why() {
    let choice = json!({
        "message": { "role": "assistant", "content": "I was about to call" },
        "finish_reason": "length"
    });
    let Turn::Unusable { reason, .. } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected unusable");
    };
    assert!(reason.contains("cut off"), "reason was: {reason}");
}

#[test]
fn malformed_arguments_are_reported_not_silently_emptied() {
    let choice = json!({
        "message": {
            "tool_calls": [{
                "id": "call_1",
                "function": { "name": "mcp__kin__semantic_locate", "arguments": "{query: broken" }
            }]
        }
    });
    let Turn::ToolCalls { calls, .. } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected tool calls");
    };
    let problem = parse::arguments_are_malformed(&calls[0].arguments)
        .expect("malformed arguments must be reported");
    assert!(problem.contains("not valid JSON"), "problem was: {problem}");
}

#[test]
fn well_formed_arguments_are_not_reported_as_malformed() {
    // The control for the test above: the same check must stay quiet on a good call.
    let choice = json!({
        "message": {
            "tool_calls": [{
                "id": "call_1",
                "function": { "name": "mcp__kin__semantic_locate", "arguments": "{\"query\": \"fine\"}" }
            }]
        }
    });
    let Turn::ToolCalls { calls, .. } = parse::parse_choice(&choice, &belt_names()) else {
        panic!("expected tool calls");
    };
    assert_eq!(parse::arguments_are_malformed(&calls[0].arguments), None);
}

fn test_belt() -> Belt {
    Belt::new(vec![(
        "kin".to_string(),
        "semantic_locate".to_string(),
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "limit": { "type": "integer" }
            },
            "required": ["query"]
        }),
    )])
}

#[test]
fn the_router_refuses_a_tool_that_is_not_on_the_belt() {
    let belt = test_belt();
    for name in [
        "bash",
        "Bash",
        "run_shell",
        "grep",
        "Grep",
        "read_file",
        "Read",
        "glob",
    ] {
        let Route::Refused(message) = belt.route(name) else {
            panic!("`{name}` must be refused, not routed");
        };
        assert!(
            message.contains("no shell") || message.contains("no tool named"),
            "the refusal must say why: {message}"
        );
    }
}

#[test]
fn the_router_routes_what_is_on_the_belt() {
    // The control: the same router must still route the real tools.
    let belt = test_belt();
    assert_eq!(
        belt.route("mcp__kin__semantic_locate"),
        Route::Kin {
            server: "kin".into(),
            tool: "semantic_locate".into()
        }
    );
    assert_eq!(belt.route("edit_file"), Route::Local(LocalTool::Edit));
    assert_eq!(belt.route("write_file"), Route::Local(LocalTool::Write));
}

#[test]
fn a_bare_kin_tool_name_is_refused_with_the_prefixed_name() {
    let belt = test_belt();
    let Route::Refused(message) = belt.route("semantic_locate") else {
        panic!("the unprefixed name is not callable");
    };
    assert!(
        message.contains("mcp__kin__semantic_locate"),
        "the refusal must name the real tool: {message}"
    );
}

#[test]
fn harness_owned_tools_never_reach_the_model() {
    for name in [
        "kin_session_start",
        "kin_session_end",
        "kin_transaction_begin",
        "kin_transaction_commit",
        "kin_transaction_abort",
    ] {
        assert!(belt::is_harness_owned(name), "{name} must be harness owned");
    }
    assert!(!belt::is_harness_owned("semantic_locate"));
    assert!(!belt::is_harness_owned("get_context_pack"));
}

#[test]
fn missing_required_arguments_are_named() {
    let belt = test_belt();
    let schema = belt.schema_for("mcp__kin__semantic_locate").unwrap();
    let problem = belt::validate_arguments(&schema, &json!({ "limit": 5 })).unwrap_err();
    assert!(problem.contains("`query`"), "problem was: {problem}");
    // The control: the same schema accepts a good call.
    assert!(belt::validate_arguments(&schema, &json!({ "query": "x", "limit": 5 })).is_ok());
}

#[test]
fn a_wrongly_typed_argument_is_named() {
    let belt = test_belt();
    let schema = belt.schema_for("mcp__kin__semantic_locate").unwrap();
    let problem =
        belt::validate_arguments(&schema, &json!({ "query": "x", "limit": "five" })).unwrap_err();
    assert!(problem.contains("`limit`"), "problem was: {problem}");
    assert!(problem.contains("integer"), "problem was: {problem}");
}

#[test]
fn an_untrusted_absence_is_read_off_the_payload() {
    // The payload lives inside content[0].text; reading the wrapper's top level finds
    // nothing, which is how an unreadable value once became a confident zero.
    let result = json!({
        "content": [{
            "type": "text",
            "text": json!({
                "results": [],
                "_kin": { "envelope_version": "1", "runtime": "RepoDaemon", "semantic_coverage": 0.4 },
                "negative": { "safe_to_conclude_absent": false, "limiting_factor": "python bodies are not indexed" }
            }).to_string()
        }],
        "isError": false
    });
    let outcome = unwrap_tool_result(&result, 12);
    assert_eq!(outcome.safe_to_conclude_absent(), Some(false));
    assert_eq!(
        outcome.limiting_factor().as_deref(),
        Some("python bodies are not indexed")
    );
    assert!(!outcome.unreadable);
    let summary = outcome.envelope_summary().expect("an envelope was present");
    assert_eq!(summary["runtime"], "RepoDaemon");
}

#[test]
fn a_trusted_absence_reads_as_trusted() {
    // The control: the same reader must report true when the verdict is true, or the
    // check above would pass for a reader that always says false.
    let result = json!({
        "content": [{ "type": "text", "text": json!({
            "results": [],
            "negative": { "safe_to_conclude_absent": true }
        }).to_string() }],
        "isError": false
    });
    let outcome = unwrap_tool_result(&result, 3);
    assert_eq!(outcome.safe_to_conclude_absent(), Some(true));
}

#[test]
fn a_result_with_no_verdict_reports_none_not_false() {
    let result = json!({
        "content": [{ "type": "text", "text": json!({ "results": [1, 2] }).to_string() }],
        "isError": false
    });
    let outcome = unwrap_tool_result(&result, 3);
    assert_eq!(outcome.safe_to_conclude_absent(), None);
    assert!(outcome.negative.is_none());
}

#[test]
fn an_mcp_error_survives_into_the_outcome() {
    // An MCP error is a successful JSON-RPC response, so isError must be read off the
    // result rather than inferred from transport success.
    let result = json!({
        "content": [{ "type": "text", "text": "no such entity" }],
        "isError": true
    });
    assert!(unwrap_tool_result(&result, 1).is_error);
}

#[test]
fn an_unparsable_structured_payload_is_unreadable_not_empty() {
    let result = json!({
        "content": [{ "type": "text", "text": "{\"results\": [ truncated" }],
        "isError": false
    });
    let outcome = unwrap_tool_result(&result, 1);
    assert!(outcome.unreadable, "a truncated payload must be unreadable");
    assert!(outcome.envelope.is_none());
    // Plain prose is not a structured payload and is not unreadable.
    let prose = json!({ "content": [{ "type": "text", "text": "3 results" }] });
    assert!(!unwrap_tool_result(&prose, 1).unreadable);
}

#[test]
fn degraded_flags_are_read_in_every_shape_the_envelope_uses() {
    let array = json!({ "content": [{ "type": "text", "text": json!({
        "_kin": { "degraded": ["embeddings", "lsp"] }
    }).to_string() }] });
    assert_eq!(
        unwrap_tool_result(&array, 1).degraded(),
        vec!["embeddings".to_string(), "lsp".to_string()]
    );

    let object = json!({ "content": [{ "type": "text", "text": json!({
        "_kin": { "degraded": { "embeddings": true, "lsp": false } }
    }).to_string() }] });
    assert_eq!(
        unwrap_tool_result(&object, 1).degraded(),
        vec!["embeddings".to_string()]
    );

    // The control: an envelope with nothing degraded reports nothing.
    let clean = json!({ "content": [{ "type": "text", "text": json!({
        "_kin": { "degraded": [] }
    }).to_string() }] });
    assert!(unwrap_tool_result(&clean, 1).degraded().is_empty());
}

#[test]
fn a_path_cannot_escape_the_repository() {
    let repo = std::path::Path::new("/tmp/kin-agent-fixture");
    for raw in ["../outside.txt", "a/../../outside.txt", "/etc/passwd", "/"] {
        assert!(
            belt::resolve_in_repo(repo, raw).is_err(),
            "`{raw}` must be refused"
        );
    }
    // The control: an ordinary relative path resolves, and so does an absolute path that
    // is genuinely inside the repository.
    assert_eq!(
        belt::resolve_in_repo(repo, "src/main.rs").unwrap(),
        repo.join("src/main.rs")
    );
    assert_eq!(
        belt::resolve_in_repo(repo, "/tmp/kin-agent-fixture/src/lib.rs").unwrap(),
        repo.join("src/lib.rs")
    );
}

#[test]
fn edit_file_refuses_an_ambiguous_find() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x\nx\n").unwrap();
    let outcome = belt::run_edit(
        dir.path(),
        &json!({ "path": "a.txt", "find": "x", "replace": "y" }),
    );
    assert!(outcome.is_error);
    assert!(outcome.text.contains("2 times"), "{}", outcome.text);
    // The file is untouched, so an ambiguous edit cannot half-apply.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        "x\nx\n"
    );
    // The control: a unique find lands.
    std::fs::write(dir.path().join("b.txt"), "hello world\n").unwrap();
    let ok = belt::run_edit(
        dir.path(),
        &json!({ "path": "b.txt", "find": "world", "replace": "kin" }),
    );
    assert!(!ok.is_error, "{}", ok.text);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("b.txt")).unwrap(),
        "hello kin\n"
    );
    assert_eq!(ok.changed.as_deref(), Some("b.txt"));
}

#[test]
fn edit_file_refuses_a_find_that_is_not_present() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
    let outcome = belt::run_edit(
        dir.path(),
        &json!({ "path": "a.txt", "find": "goodbye", "replace": "y" }),
    );
    assert!(outcome.is_error);
    assert!(outcome.text.contains("does not appear"), "{}", outcome.text);
}

#[test]
fn write_file_creates_parents_and_reports_which_path_changed() {
    let dir = tempfile::tempdir().unwrap();
    let outcome = belt::run_write(
        dir.path(),
        &json!({ "path": "docs/new.md", "content": "# hi\n" }),
    );
    assert!(!outcome.is_error, "{}", outcome.text);
    assert_eq!(outcome.changed.as_deref(), Some("docs/new.md"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("docs/new.md")).unwrap(),
        "# hi\n"
    );
}

#[test]
fn the_belt_exposes_only_kin_tools_plus_the_two_local_ones() {
    let belt = test_belt();
    let names: Vec<&str> = belt.names().iter().map(String::as_str).collect();
    assert_eq!(
        names,
        vec!["edit_file", "mcp__kin__semantic_locate", "write_file"]
    );
    // No shell, search or read tool exists to be routed, which is the policy.
    for absent in ["bash", "shell", "grep", "rg", "find", "read_file", "cat"] {
        assert!(
            !belt.names().contains(absent),
            "`{absent}` must not be in the belt"
        );
    }
}

#[test]
fn base_urls_normalize_to_one_endpoint() {
    use crate::provider::ProviderConfig;
    for raw in [
        "http://127.0.0.1:1234",
        "http://127.0.0.1:1234/",
        "http://127.0.0.1:1234/v1",
        "http://127.0.0.1:1234/v1/",
    ] {
        assert_eq!(
            ProviderConfig::normalize_base_url(raw),
            "http://127.0.0.1:1234/v1",
            "for {raw}"
        );
    }
}

#[test]
fn a_named_api_key_variable_that_is_unset_fails_loudly() {
    use crate::provider::ProviderConfig;
    // Silently sending no key would surface later as a 401 that reads like a bad model id.
    assert!(ProviderConfig::api_key_from_env(Some("KIN_AGENT_KEY_THAT_IS_NOT_SET")).is_err());
    assert_eq!(ProviderConfig::api_key_from_env(None).unwrap(), None);
}

#[test]
fn a_qualified_tool_name_splits_back_into_its_halves() {
    assert_eq!(
        belt::split_qualified("mcp__kin__semantic_locate"),
        Some(("kin", "semantic_locate"))
    );
    // A tool name carrying underscores survives, because the split is on the FIRST `__`
    // after the prefix rather than the last.
    assert_eq!(
        belt::split_qualified("mcp__nk-agent__kin_transaction_stage"),
        Some(("nk-agent", "kin_transaction_stage"))
    );
    // Controls: nothing that is not a qualified name splits.
    assert_eq!(belt::split_qualified("edit_file"), None);
    assert_eq!(belt::split_qualified("mcp__kin"), None);
    assert_eq!(belt::split_qualified("mcp____tool"), None);
}

#[test]
fn two_servers_keep_their_tools_distinguishable() {
    let belt = Belt::new(vec![
        (
            "green".to_string(),
            "semantic_locate".to_string(),
            json!({ "type": "object" }),
        ),
        (
            "brown".to_string(),
            "semantic_locate".to_string(),
            json!({ "type": "object" }),
        ),
    ]);
    // Same tool on two servers is two callable names, and each routes to its own server.
    assert_eq!(
        belt.route("mcp__green__semantic_locate"),
        Route::Kin {
            server: "green".into(),
            tool: "semantic_locate".into()
        }
    );
    assert_eq!(
        belt.route("mcp__brown__semantic_locate"),
        Route::Kin {
            server: "brown".into(),
            tool: "semantic_locate".into()
        }
    );
    // A server nobody attached is refused, not silently routed to the other one.
    assert!(matches!(
        belt.route("mcp__other__semantic_locate"),
        Route::Refused(_)
    ));
    // The belt the MODEL sees must carry both names too, not just the router. These are
    // separate structures and a break in one would otherwise pass on the other's evidence.
    let names: Vec<&str> = belt.names().iter().map(String::as_str).collect();
    assert!(
        names.contains(&"mcp__green__semantic_locate"),
        "the green server's tool must be offered: {names:?}"
    );
    assert!(
        names.contains(&"mcp__brown__semantic_locate"),
        "the brown server's tool must be offered: {names:?}"
    );
    assert_eq!(
        names.iter().filter(|n| n.starts_with("mcp__")).count(),
        2,
        "two servers means two distinct Kin tool names: {names:?}"
    );
}
