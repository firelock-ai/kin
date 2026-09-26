// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Unit tests for the parsers, the router, the envelope reading and the Kin-only belt.

use crate::belt::{self, Belt, Route};
use crate::mcp::unwrap_tool_result;
use crate::parse::{self, CallShape, Turn};
use serde_json::json;
use std::collections::BTreeSet;

fn belt_names() -> BTreeSet<String> {
    ["mcp__kin__semantic_locate"]
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
    Belt::new(vec![kin_tool(0, "semantic_locate", None)])
}

/// One belt entry as a run would build it: bare name from the server, exposed name from
/// that server's prefix.
fn kin_tool(server: usize, bare: &str, label: Option<&str>) -> belt::KinTool {
    belt::KinTool {
        folded: false,
        server,
        bare: bare.to_string(),
        exposed: format!("{}{bare}", belt::tool_prefix(label)),
        description: format!("test tool {bare}"),
        schema: json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "limit": { "type": "integer" }
            },
            "required": ["query"]
        }),
    }
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
            server: 0,
            tool: "semantic_locate".into()
        }
    );
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
        "kin_session_heartbeat",
        "kin_transaction_begin",
        // Stage and validate both need a transaction id, and begin is the only honest
        // source of one. Exposing either without begin leaves a model nothing to do but
        // invent an id.
        "kin_transaction_stage",
        "kin_transaction_validate",
        "kin_transaction_commit",
        "kin_transaction_abort",
    ] {
        assert!(belt::is_harness_owned(name), "{name} must be harness owned");
    }
    assert!(!belt::is_harness_owned("semantic_locate"));
    assert!(!belt::is_harness_owned("get_context_pack"));
    assert!(!belt::is_harness_owned("kin_mutate"));
}

#[test]
fn the_belt_has_no_file_tools_and_refuses_them_with_a_mutate_hint() {
    let tool = crate::belt::KinTool {
        folded: false,
        server: 0,
        bare: "kin_mutate".into(),
        exposed: "mcp__kin__kin_mutate".into(),
        description: "Atomically mutate graph".into(),
        schema: json!({ "type": "object" }),
    };
    let belt = Belt::new(vec![tool]);
    assert_eq!(belt.names().len(), 1);
    assert!(belt.names().contains("mcp__kin__kin_mutate"));
    assert!(!belt.names().contains("edit_file"));
    assert!(!belt.names().contains("write_file"));

    for name in ["edit_file", "write_file"] {
        let Route::Refused(refusal) = belt.route(name) else {
            panic!("{name} must be refused: the file tools are retired");
        };
        assert!(
            refusal.contains("`mcp__kin__kin_mutate`"),
            "the refusal should point to kin_mutate: {refusal}"
        );
        assert!(
            refusal.contains("file tools are retired"),
            "the refusal should say the file tools are gone, not missing: {refusal}"
        );
        assert!(
            refusal.contains("There is no file creation"),
            "the refusal should not imply a way to create a file: {refusal}"
        );
    }

    // What the model is actually shown. `names` and `route` are the harness's
    // own view; `to_specs` is the tools array that goes out on every turn, and a
    // tool absent from the first two but present in the third is a tool the
    // model will call.
    let specs = belt.to_specs();
    let served: Vec<&str> = specs
        .iter()
        .filter_map(|spec| spec["function"]["name"].as_str())
        .collect();
    assert_eq!(
        served,
        vec!["mcp__kin__kin_mutate"],
        "the belt serves the Kin tools and nothing else"
    );
    assert!(belt.schema_for("edit_file").is_none());
    assert!(belt.schema_for("write_file").is_none());
}

/// A belt that carries no `kin_mutate` must not point the model at it: a refusal
/// naming a tool the belt lacks sends the model into a second refusal.
#[test]
fn a_file_tool_refusal_on_a_read_only_belt_names_no_write_tool() {
    let belt = Belt::new(vec![kin_tool(0, "semantic_locate", None)]);
    let Route::Refused(refusal) = belt.route("edit_file") else {
        panic!("edit_file must be refused");
    };
    assert!(!refusal.contains("kin_mutate"), "{refusal}");
    assert!(
        refusal.contains("no tool that changes code"),
        "the refusal must say the run is read-only: {refusal}"
    );
}

/// `KIN_AGENT_PURE_KIN` means what kin-core's env registry says a boolean means.
/// A false value asked for the file tools, which are retired, so it is refused by
/// name; every other value, and no value, runs the one belt there is.
///
/// Read through the pure functions rather than the process environment, because
/// tests share one process and a test that sets an environment variable races
/// every other test that reads it. The run's own refusal is proven in a child
/// process below.
#[test]
fn the_pure_kin_switch_reads_booleans_the_way_the_env_registry_does() {
    for on in ["1", "true", "yes", "on", "TRUE", " On "] {
        assert!(
            belt::pure_kin_requested(Some(on)),
            "{on:?} asks for the Kin-only belt"
        );
        assert_eq!(belt::refuse_file_tools(Some(on)), Ok(()), "{on:?}");
    }
    for off in ["0", "false", "no", "off", "OFF", " Off "] {
        assert!(
            !belt::pure_kin_requested(Some(off)),
            "{off:?} asked for the file tools"
        );
        let refusal = belt::refuse_file_tools(Some(off)).expect_err("a false value is refused");
        assert_eq!(
            refusal,
            format!(
                "KIN_AGENT_PURE_KIN={} no longer adds file tools: Kin agents change code \
                 through entities, and the local file tools are retired. Unset \
                 KIN_AGENT_PURE_KIN, or set it to true, to run.",
                off.trim()
            )
        );
    }
    // Unset is the Kin-only belt, and so is a value the registry cannot read:
    // startup validation reports the typo, the default is not guessed away.
    assert!(belt::pure_kin_requested(None), "unset is the Kin-only belt");
    assert_eq!(belt::refuse_file_tools(None), Ok(()));
    for unread in ["", "maybe"] {
        assert!(
            belt::pure_kin_requested(Some(unread)),
            "{unread:?} leaves the Kin-only belt"
        );
        assert_eq!(belt::refuse_file_tools(Some(unread)), Ok(()), "{unread:?}");
    }
}

/// Marks a child process running one run-refusal test on its own.
const PURE_KIN_CHILD: &str = "KIN_AGENT_PURE_KIN_TEST_CHILD";

/// Whether this process is the child running `test` on its own.
fn in_pure_kin_child(test: &str) -> bool {
    std::env::var(PURE_KIN_CHILD).as_deref() == Ok(test)
}

/// Run `test` again in a child process with `KIN_AGENT_PURE_KIN` set to `value`,
/// or removed for `None`, and fail unless the child ran it and it passed.
///
/// The variable is process-wide and every run reads it, so it is set only in a
/// child that runs this one test, never under tests running concurrently here.
fn run_in_pure_kin_child(test: &str, value: Option<&str>) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", &format!("tests::{test}"), "--nocapture"])
        .env(PURE_KIN_CHILD, test);
    match value {
        Some(value) => child.env("KIN_AGENT_PURE_KIN", value),
        None => child.env_remove("KIN_AGENT_PURE_KIN"),
    };
    let output = child.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child for {value:?} failed or ran nothing: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A run config that would fail loudly if it got far enough to use anything: the
/// graph server is a binary that does not exist and the endpoint is a closed port.
fn unreachable_config(dir: &std::path::Path) -> crate::AgentConfig {
    crate::AgentConfig {
        task: "Rename greet.".into(),
        system_prompt: None,
        repo: dir.to_path_buf(),
        out_dir: dir.join("out"),
        provider: crate::ProviderConfig {
            base_url: crate::ProviderConfig::normalize_base_url("http://127.0.0.1:9"),
            model: "fixture-model".into(),
            api_key: None,
            temperature: None,
            request_timeout: std::time::Duration::from_secs(1),
        },
        mcp_command: vec!["kin-agent-no-such-binary".into()],
        extra_servers: Vec::new(),
        mcp_timeout: std::time::Duration::from_secs(1),
        max_tool_calls: 1,
        deadline: std::time::Duration::from_secs(5),
        context: crate::ContextWindow {
            tokens: 32_768,
            source: crate::ContextSource::Flag,
        },
        max_result_bytes: None,
        tool_profile: None,
    }
}

/// A false `KIN_AGENT_PURE_KIN` used to put `edit_file` and `write_file` on the
/// belt. Now the run refuses to start and says why, through the same entry
/// point `kin agent run` calls, before it writes a transcript, starts a graph
/// server or contacts the model.
#[test]
fn the_run_refuses_to_start_on_a_false_pure_kin_value() {
    const TEST: &str = "the_run_refuses_to_start_on_a_false_pure_kin_value";
    if !in_pure_kin_child(TEST) {
        for value in ["false", "0", " Off "] {
            run_in_pure_kin_child(TEST, Some(value));
        }
        return;
    }
    let raw = std::env::var("KIN_AGENT_PURE_KIN").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = unreachable_config(dir.path());
    let out = config.out_dir.clone();
    let refusal = crate::run(config).expect_err("a false value must not start a run");
    assert_eq!(
        refusal.to_string(),
        format!(
            "KIN_AGENT_PURE_KIN={} no longer adds file tools: Kin agents change code through \
             entities, and the local file tools are retired. Unset KIN_AGENT_PURE_KIN, or set \
             it to true, to run.",
            raw.trim()
        )
    );
    // The transcript is the run's first write, ahead of the graph server and the
    // model, so its absence proves the refusal came before all three.
    assert!(!out.exists(), "a refused run must write nothing");
}

/// The control for the refusal above: a true value and no value at all both get
/// past it, so the run goes on to fail for the reason this config sets up, the
/// graph server that is not there, and records that failure in its transcript.
#[test]
fn a_true_or_unset_pure_kin_value_runs() {
    const TEST: &str = "a_true_or_unset_pure_kin_value_runs";
    if !in_pure_kin_child(TEST) {
        for value in [Some("true"), Some("1"), None] {
            run_in_pure_kin_child(TEST, value);
        }
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = unreachable_config(dir.path());
    let out = config.out_dir.clone();
    let outcome = crate::run(config).expect("the run starts and reports its own failure");
    assert_eq!(outcome.status, crate::ExitStatus::McpError);
    assert!(out.join("transcript.jsonl").exists());
}

/// The built-in prompt describes only the write tool the belt actually carries.
///
/// A prompt naming a tool the belt lacks is a false instruction: under
/// `--tool-profile agent-query` no `kin_mutate` is served, and a model told to
/// call it spends its turns being refused.
#[test]
fn the_system_prompt_names_only_the_write_tool_the_belt_carries() {
    let mutate = kin_tool(0, "kin_mutate", None);
    let locate = kin_tool(0, "semantic_locate", None);

    let entity = crate::run::system_prompt_for(&Belt::new(vec![mutate.clone(), locate.clone()]));
    assert!(entity.contains("mcp__kin__kin_mutate") && entity.contains("name the entity"));

    let read_only = crate::run::system_prompt_for(&Belt::new(vec![locate.clone()]));
    assert!(
        read_only.contains("no tool that changes code"),
        "{read_only}"
    );
    assert!(
        !read_only.contains("kin_mutate") && !read_only.contains("edit_file"),
        "{read_only}"
    );

    // Every shape keeps the shared head and tail, so only the one paragraph moved.
    for prompt in [&entity, &read_only] {
        assert!(prompt.contains("Kin is your only way to look at the repository"));
        assert!(prompt.contains("Work in small steps"));
    }
}

/// The default prompt teaches one way to change code: `kin_mutate`, naming an entity.
/// It offers no file verb and no file tool, and it says plainly that there is no file
/// creation, so a model that needs something `kin_mutate` cannot make stops instead of
/// hunting for a way around the gap.
///
/// An entity-level verb may appear here as `kin_mutate` grows one. What must not come
/// back is the file-level shape: a path as the target, a whole file rewritten, or a
/// local file tool.
#[test]
fn the_default_prompt_teaches_entity_changes_and_offers_no_file_verb() {
    let prompt = crate::DEFAULT_SYSTEM_PROMPT;
    for gone in [
        "edit_file",
        "write_file",
        "'replace'",
        "repository-relative path",
        "A file the graph has never seen",
        "rewriting whole",
    ] {
        assert!(!prompt.contains(gone), "the prompt still mentions {gone}");
    }
    // As a word, too. `replaces` in the update instruction is a different word and
    // stays: the body replaces the entity's whole span.
    let words: BTreeSet<String> = prompt
        .split(|character: char| !character.is_alphanumeric())
        .map(str::to_ascii_lowercase)
        .collect();
    assert!(
        !words.contains("replace"),
        "the prompt still offers the replace verb"
    );
    assert!(prompt.contains("verb 'update'"));
    assert!(prompt.contains("send the whole body back, not a fragment"));
    assert!(
        prompt.contains(
            "Your tools are the ones on your belt and no others: this repository is a graph, \
             and a change to it is a change to an entity. Every change goes through \
             mcp__kin__kin_mutate, including a new entity if its operations offer one; there \
             is no file creation. If the change needs something kin_mutate cannot make, stop \
             and say so."
        ),
        "the prompt must state that there is no file creation: {prompt}"
    );
}

/// The routing rule for the literal-lookup tool: named in the prompt, on the
/// default belt (never withheld behind `KIN_AGENT_BELT=wide`), and routed by
/// bare name like any other Kin tool, with no fold and no special case needed.
#[test]
fn lexical_lookup_is_on_the_default_belt_and_named_in_its_routing_rule() {
    let locate = kin_tool(0, "semantic_locate", None);
    let lexical_lookup = kin_tool(0, "lexical_lookup", None);

    let prompt =
        crate::run::system_prompt_for(&Belt::new(vec![locate.clone(), lexical_lookup.clone()]));
    assert!(
        prompt.contains("mcp__kin__lexical_lookup"),
        "the routing rule must name the tool: {prompt}"
    );
    assert!(
        prompt.contains("inconclusive verdict"),
        "the routing rule must name the second trigger (an inconclusive structural verdict): {prompt}"
    );

    assert!(
        !belt::is_opt_in("lexical_lookup"),
        "lexical_lookup must ride the default belt, not KIN_AGENT_BELT=wide"
    );

    let belt = Belt::new(vec![locate, lexical_lookup]);
    assert_eq!(
        belt.route("mcp__kin__lexical_lookup"),
        Route::Kin {
            server: 0,
            tool: "lexical_lookup".to_string(),
        },
        "an ordinary declared Kin tool routes by its bare name with no fold"
    );
}

/// The harness supplies the session `kin_mutate` needs and the model cannot see.
///
/// `kin_session_start` is harness-owned, so the model never learns the session
/// id the run opened. Sending `kin_mutate` without one used to fall through to
/// the MCP server's own in-process registry, which in daemon mode is not the
/// authority: it invents an id the daemon has never heard of and
/// `kin_transaction_begin` refuses it. On a pure-Kin belt that is the only write
/// tool there is, so the belt would have had no way to commit at all.
#[test]
fn the_harness_fills_in_the_session_a_mutate_needs_and_leaves_every_other_call_alone() {
    let mutate = json!({ "operations": [{ "verb": "update", "target": "Widget", "body": "x" }] });
    let sent = crate::run::with_harness_session(&mutate, "kin_mutate", Some("sess-1"));
    assert_eq!(sent["session_id"], json!("sess-1"));
    assert_eq!(sent["operations"], mutate["operations"]);

    // A session the model named itself survives, so a caller's mistake earns
    // the refusal it should rather than a silent correction.
    let named = json!({ "operations": [], "session_id": "the-model-said-this" });
    let sent = crate::run::with_harness_session(&named, "kin_mutate", Some("sess-1"));
    assert_eq!(sent["session_id"], json!("the-model-said-this"));

    // An empty one is not a session. A model that emits the key with nothing in
    // it has named nothing, and filling it is the same correction as filling an
    // absent key.
    let blank = json!({ "operations": [], "session_id": "  " });
    let sent = crate::run::with_harness_session(&blank, "kin_mutate", Some("sess-1"));
    assert_eq!(sent["session_id"], json!("sess-1"));

    // The controls. Every other tool keeps the exact arguments the model wrote,
    // and a run holding no session of its own invents nothing to fill with.
    let read = json!({ "entity_id": "abc" });
    assert_eq!(
        crate::run::with_harness_session(&read, "get_entity_source", Some("sess-1")),
        read
    );
    assert_eq!(
        crate::run::with_harness_session(&mutate, "kin_mutate", None),
        mutate
    );
}

#[test]
fn a_second_repository_of_the_same_name_gets_its_own_label() {
    use std::collections::BTreeSet;
    let mut taken = BTreeSet::new();
    let first = belt::server_label(std::path::Path::new("/tmp/one/kin"), &taken);
    assert_eq!(first, "kin");
    taken.insert(first);
    // Two checkouts of the same repository is the ordinary brownfield case, and sharing a
    // prefix would make the model's call ambiguous rather than merely ugly.
    let second = belt::server_label(std::path::Path::new("/other/kin"), &taken);
    assert_eq!(second, "kin_2");
    // A name a tool prefix cannot carry is reduced, not passed through.
    let odd = belt::server_label(std::path::Path::new("/tmp/my repo.v2"), &BTreeSet::new());
    assert_eq!(odd, "my_repo_v2");
}

/// One belt entry carrying a schema close enough to the real one to fold.
fn traversal_tool(server: usize, bare: &str, label: Option<&str>) -> belt::KinTool {
    let schema = match bare {
        belt::TRACE_ONE_ENDPOINT => json!({
            "type": "object",
            "properties": {
                "focal": { "type": "string", "description": "The entity to walk from." },
                "target": { "type": "string" },
                "direction": { "type": "string", "enum": ["calls", "callers", "both"] },
                "depth": { "type": "integer", "default": 3 },
                "include_body": { "type": "boolean", "default": false },
                "limit_per_step": { "type": "integer", "default": 25 },
                "max_chars": { "type": "integer", "default": 12000 }
            },
            "required": ["focal"]
        }),
        _ => json!({
            "type": "object",
            "properties": {
                "from": { "type": "string", "description": "One end, by name, id or name@file." },
                "to": { "type": "string", "description": "The other end." },
                "direction": { "type": "string", "enum": ["forward", "reverse", "either"] },
                "max_depth": { "type": "integer", "default": 6 },
                "limit": { "type": "integer", "default": 3 },
                "max_chars": { "type": "integer", "default": 12000 }
            },
            "required": ["from", "to"]
        }),
    };
    belt::KinTool {
        folded: false,
        server,
        bare: bare.to_string(),
        exposed: format!("{}{bare}", belt::tool_prefix(label)),
        description: format!("test tool {bare}"),
        schema,
    }
}

#[test]
fn the_two_traversal_tools_arrive_on_the_belt_as_one() {
    let mut tools = vec![
        kin_tool(0, "semantic_locate", None),
        traversal_tool(0, belt::TRACE_ONE_ENDPOINT, None),
        traversal_tool(0, belt::TRACE_TWO_ENDPOINT, None),
    ];
    belt::fold_traversal(&mut tools);
    let names: Vec<&str> = tools.iter().map(|tool| tool.exposed.as_str()).collect();
    assert_eq!(
        names,
        vec!["mcp__kin__semantic_locate", "mcp__kin__trace"],
        "the belt should carry one traversal tool, not two"
    );
    let folded = &tools[1];
    assert!(folded.folded, "the fold must be marked, not inferred");
    let properties = folded.schema["properties"].as_object().expect("properties");
    for name in [
        "from",
        "to",
        "direction",
        "depth",
        "include_body",
        "limit_per_step",
    ] {
        assert!(
            properties.contains_key(name),
            "the folded tool lost {name}: {:?}",
            properties.keys().collect::<Vec<_>>()
        );
    }
    // The bounds and defaults the server declared travel with the property, so
    // the belt cannot drift from the schema it is folding.
    assert_eq!(properties["limit_per_step"]["default"], json!(25));
    assert_eq!(
        properties["from"]["description"],
        json!("One end, by name, id or name@file.")
    );
}

#[test]
fn a_server_declaring_only_one_traversal_tool_is_left_alone() {
    let mut tools = vec![traversal_tool(0, belt::TRACE_ONE_ENDPOINT, None)];
    belt::fold_traversal(&mut tools);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].exposed, "mcp__kin__trace_data_flow");
    assert!(!tools[0].folded);
}

#[test]
fn naming_both_ends_routes_the_folded_call_to_the_two_ended_tool() {
    let mut tools = vec![
        traversal_tool(0, belt::TRACE_ONE_ENDPOINT, None),
        traversal_tool(0, belt::TRACE_TWO_ENDPOINT, None),
    ];
    belt::fold_traversal(&mut tools);
    let belt = Belt::new(tools);

    let two_ended = belt.route_call(
        "mcp__kin__trace",
        &json!({ "from": "apiRun", "to": "httpRequest", "direction": "both", "depth": 4 }),
    );
    assert_eq!(
        two_ended.route,
        Route::Kin {
            server: 0,
            tool: belt::TRACE_TWO_ENDPOINT.into()
        }
    );
    assert_eq!(
        two_ended.arguments,
        json!({ "from": "apiRun", "to": "httpRequest", "direction": "either", "max_depth": 4 }),
        "the two-ended tool takes max_depth and its own direction words"
    );

    let one_ended = belt.route_call(
        "mcp__kin__trace",
        &json!({ "from": "apiRun", "direction": "reverse", "depth": 2 }),
    );
    assert_eq!(
        one_ended.route,
        Route::Kin {
            server: 0,
            tool: belt::TRACE_ONE_ENDPOINT.into()
        }
    );
    assert_eq!(
        one_ended.arguments,
        json!({ "focal": "apiRun", "direction": "callers", "depth": 2 }),
        "the one-ended tool takes focal and its own direction words"
    );
}

#[test]
fn an_empty_to_is_read_as_one_ended_rather_than_refused() {
    let mut tools = vec![
        traversal_tool(0, belt::TRACE_ONE_ENDPOINT, None),
        traversal_tool(0, belt::TRACE_TWO_ENDPOINT, None),
    ];
    belt::fold_traversal(&mut tools);
    let belt = Belt::new(tools);
    let routed = belt.route_call("mcp__kin__trace", &json!({ "from": "apiRun", "to": "  " }));
    assert_eq!(
        routed.route,
        Route::Kin {
            server: 0,
            tool: belt::TRACE_ONE_ENDPOINT.into()
        }
    );
    assert_eq!(routed.arguments, json!({ "focal": "apiRun" }));
}

#[test]
fn the_fold_keeps_two_servers_apart() {
    let mut tools = vec![
        traversal_tool(0, belt::TRACE_ONE_ENDPOINT, Some("alpha")),
        traversal_tool(0, belt::TRACE_TWO_ENDPOINT, Some("alpha")),
        traversal_tool(1, belt::TRACE_ONE_ENDPOINT, Some("beta")),
        traversal_tool(1, belt::TRACE_TWO_ENDPOINT, Some("beta")),
    ];
    belt::fold_traversal(&mut tools);
    let names: Vec<&str> = tools.iter().map(|tool| tool.exposed.as_str()).collect();
    assert_eq!(names, vec!["mcp__kin_alpha__trace", "mcp__kin_beta__trace"]);
    assert_eq!(tools[0].server, 0);
    assert_eq!(tools[1].server, 1);
}

#[test]
fn the_default_belt_withholds_the_opt_in_tools_and_the_wide_one_does_not() {
    assert_eq!(
        belt::BeltProfile::from_value(None),
        belt::BeltProfile::Default
    );
    assert_eq!(
        belt::BeltProfile::from_value(Some(" WIDE ")),
        belt::BeltProfile::Wide
    );
    assert_eq!(
        belt::BeltProfile::from_value(Some("nonsense")),
        belt::BeltProfile::Default,
        "an unreadable value must not quietly widen the belt"
    );
    for withheld in ["graph_neighborhood", "kin_provenance_query"] {
        assert!(belt::is_opt_in(withheld), "{withheld} should be opt-in");
    }
    // The capabilities an agent needs to answer, edit and publish stay on the
    // default belt. impact_analysis is here deliberately: "what breaks if I
    // change this" is the question Kin is described as answering.
    for kept in [
        "semantic_locate",
        "semantic_search",
        "get_context_pack",
        "get_entity_source",
        "find_references",
        "impact_analysis",
        "kin_mutate",
        "trace_data_flow",
        "trace_path",
        "kin_graph_status",
    ] {
        assert!(
            !belt::is_opt_in(kept),
            "{kept} must stay on the default belt"
        );
    }
    // And nothing the harness owns is listed here, or it would be withheld twice
    // and the reason a reader finds would be the wrong one.
    for withheld in ["graph_neighborhood", "kin_provenance_query"] {
        assert!(
            !belt::is_harness_owned(withheld),
            "{withheld} is already withheld as harness-owned"
        );
    }
}

#[test]
fn tool_prefixes_separate_two_servers_and_a_bare_name_names_both() {
    let belt = Belt::new(vec![
        kin_tool(0, "semantic_locate", Some("alpha")),
        kin_tool(1, "semantic_locate", Some("beta")),
    ]);
    assert_eq!(
        belt.route("mcp__kin_alpha__semantic_locate"),
        Route::Kin {
            server: 0,
            tool: "semantic_locate".into()
        }
    );
    assert_eq!(
        belt.route("mcp__kin_beta__semantic_locate"),
        Route::Kin {
            server: 1,
            tool: "semantic_locate".into()
        }
    );
    // A bare name is ambiguous across servers, so the refusal names every form rather than
    // choosing a repository on the model's behalf.
    let Route::Refused(message) = belt.route("semantic_locate") else {
        panic!("a bare name must be refused when two servers declare it");
    };
    assert!(
        message.contains("mcp__kin_alpha__semantic_locate")
            && message.contains("mcp__kin_beta__semantic_locate"),
        "the refusal must name both prefixed forms: {message}"
    );
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
                "_kin": {
                    "envelope_version": 2, "runtime": "repo-daemon", "semantic_coverage": 0.4,
                    "verdict": { "state": "inconclusive", "limiting_factor": "coverage_partial" }
                },
                "negative": {
                    "safe_to_conclude_absent": false,
                    "trust_reason": "coverage_partial: the semantic index is incomplete"
                }
            }).to_string()
        }],
        "isError": false
    });
    let outcome = unwrap_tool_result(&result, 12);
    assert_eq!(outcome.safe_to_conclude_absent(), Some(false));
    assert_eq!(
        outcome.limiting_factor().as_deref(),
        Some("coverage_partial"),
        "the verdict's codes are the factor a reader acts on"
    );
    assert!(!outcome.unreadable);
    let summary = outcome.envelope_summary().expect("an envelope was present");
    assert_eq!(summary["runtime"], "repo-daemon");
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
fn a_labelled_belt_names_its_own_mutate_prefix_in_the_refusal() {
    // With several repositories attached each server's tools carry a label, so
    // `mcp__kin__kin_mutate` is a name nothing on this belt answers to. A hint that used
    // it, or dropped the prefix entirely, would send the model at a tool that does not
    // exist, which is the same dead end as no hint at all.
    let belt = Belt::new(vec![kin_tool(0, "kin_mutate", Some("cli90"))]);
    let Route::Refused(_) = belt.route("bash") else {
        panic!("an off-belt tool is refused");
    };
    let Route::Refused(refusal) = belt.route("edit_file") else {
        panic!("edit_file must be refused");
    };
    assert!(
        refusal.contains("`mcp__kin_cli90__kin_mutate`"),
        "the hint must name a tool this belt actually carries: {refusal}"
    );
}

#[test]
fn the_belt_exposes_only_kin_tools() {
    let belt = test_belt();
    let names: Vec<&str> = belt.names().iter().map(String::as_str).collect();
    assert_eq!(names, vec!["mcp__kin__semantic_locate"]);
    // No shell, search, read or write tool exists to be routed, which is the policy.
    for absent in [
        "bash",
        "shell",
        "grep",
        "rg",
        "find",
        "read_file",
        "cat",
        "edit_file",
        "write_file",
    ] {
        assert!(
            !belt.names().contains(absent),
            "`{absent}` must not be in the belt"
        );
        assert!(
            matches!(belt.route(absent), Route::Refused(_)),
            "`{absent}` must be refused"
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
fn the_context_window_is_read_off_each_server_shape_that_names_one() {
    use crate::provider::{
        context_from_lmstudio_model, context_from_lmstudio_models, context_from_model_list,
    };
    // vLLM names the served window on its OpenAI-compatible list, OpenRouter names the
    // model's, and an entry for another model says nothing about this one.
    let vllm = json!({ "data": [
        { "id": "other", "max_model_len": 4096 },
        { "id": "qwen", "max_model_len": 32768 }
    ]});
    assert_eq!(context_from_model_list(&vllm, "qwen"), Some(32_768));
    let openrouter = json!({ "data": [{ "id": "x/y", "context_length": 200000.0 }] });
    assert_eq!(context_from_model_list(&openrouter, "x/y"), Some(200_000));
    // LM Studio's compatible list names nothing, which must read as nothing.
    let bare = json!({ "data": [{ "id": "qwen/qwen3.8-27b", "object": "model" }] });
    assert_eq!(context_from_model_list(&bare, "qwen/qwen3.8-27b"), None);

    // LM Studio's own list: the loaded instance's context, the smallest when there are two,
    // and an instance addressed by its own id counts on its own.
    let lmstudio = json!({ "models": [
        { "key": "qwen/qwen3.8-27b", "max_context_length": 262144, "loaded_instances": [
            { "id": "qwen/qwen3.8-27b", "config": { "context_length": 131072 } },
            { "id": "qwen/qwen3.8-27b:2", "config": { "context_length": 65536 } }
        ]},
        { "key": "gpt-oss-20b", "max_context_length": 131072, "loaded_instances": [] }
    ]});
    assert_eq!(
        context_from_lmstudio_models(&lmstudio, "qwen/qwen3.8-27b"),
        Some(65_536)
    );
    assert_eq!(
        context_from_lmstudio_models(&lmstudio, "qwen/qwen3.8-27b:2"),
        Some(65_536)
    );
    // A model that is not loaded has a maximum and no window, and the maximum is never used.
    assert_eq!(context_from_lmstudio_models(&lmstudio, "gpt-oss-20b"), None);
    assert_eq!(
        context_from_lmstudio_model(&json!({ "max_context_length": 131072 })),
        None
    );
    assert_eq!(
        context_from_lmstudio_model(&json!({ "loaded_context_length": 8192 })),
        Some(8_192)
    );
    // A zero is not a window.
    assert_eq!(
        context_from_model_list(
            &json!({ "data": [{ "id": "z", "context_length": 0 }] }),
            "z"
        ),
        None
    );
}

#[test]
fn the_origin_is_the_server_root_beside_the_compatible_api() {
    use crate::provider::ProviderConfig;
    let config = ProviderConfig {
        base_url: ProviderConfig::normalize_base_url("http://127.0.0.1:1234"),
        model: "m".into(),
        api_key: None,
        temperature: None,
        request_timeout: std::time::Duration::from_secs(1),
    };
    assert_eq!(config.origin(), "http://127.0.0.1:1234");
}

#[test]
fn a_named_api_key_variable_that_is_unset_fails_loudly() {
    use crate::provider::ProviderConfig;
    // Silently sending no key would surface later as a 401 that reads like a bad model id.
    assert!(ProviderConfig::api_key_from_env(Some("KIN_AGENT_KEY_THAT_IS_NOT_SET")).is_err());
    assert_eq!(ProviderConfig::api_key_from_env(None).unwrap(), None);
}

/// The heartbeat cadence comes from the window the session reply itself names, at its top
/// level or one level down, and a reply that names none, or zero, gets no cadence at all.
#[test]
fn a_session_reply_names_its_idle_window_or_none() {
    use crate::mcp::ToolOutcome;
    use crate::run::session_idle_timeout;
    use std::time::Duration;
    let reply = |text: &str| ToolOutcome {
        text: text.to_string(),
        is_error: false,
        envelope: None,
        negative: None,
        unreadable: false,
        wall_ms: 0,
    };
    assert_eq!(
        session_idle_timeout(&reply(r#"{"session_id": "s", "idle_timeout_secs": 1800}"#)),
        Some(Duration::from_secs(1800))
    );
    assert_eq!(
        session_idle_timeout(&reply(
            r#"{"session": {"session_id": "s", "idle_timeout_secs": 90}}"#
        )),
        Some(Duration::from_secs(90))
    );
    // An in-process session reports no window, and a zero is not one.
    assert_eq!(session_idle_timeout(&reply(r#"{"session_id": "s"}"#)), None);
    assert_eq!(
        session_idle_timeout(&reply(r#"{"session_id": "s", "idle_timeout_secs": 0}"#)),
        None
    );
    assert_eq!(session_idle_timeout(&reply("not json")), None);
}

/// The reader reads the two fields Kin sends: the verdict's codes first, and the
/// absence gate's own reason when no verdict rides the response.
#[test]
fn limiting_factor_reads_the_verdict_codes_then_the_trust_reason() {
    let response = |kin: serde_json::Value, negative: serde_json::Value| {
        unwrap_tool_result(
            &json!({
                "content": [{
                    "type": "text",
                    "text": json!({ "results": [], "_kin": kin, "negative": negative }).to_string()
                }],
                "isError": false
            }),
            1,
        )
    };
    let both = response(
        json!({
            "envelope_version": 2,
            "runtime": "repo-daemon",
            "verdict": { "state": "inconclusive", "limiting_factor": "coverage_partial; retrieval_degraded" }
        }),
        json!({
            "safe_to_conclude_absent": false,
            "trust_reason": "coverage_partial: the semantic index is incomplete"
        }),
    );
    assert_eq!(
        both.limiting_factor().as_deref(),
        Some("coverage_partial; retrieval_degraded")
    );
    let reason_only = response(
        json!({ "envelope_version": 2, "runtime": "repo-daemon" }),
        json!({
            "safe_to_conclude_absent": false,
            "trust_reason": "coverage_partial: the semantic index is incomplete"
        }),
    );
    assert_eq!(
        reason_only.limiting_factor().as_deref(),
        Some("coverage_partial: the semantic index is incomplete")
    );
}

/// A key Kin never sends is not read. `negative.limiting_factor` was read while
/// every real response carried `trust_reason`, so the model was told the factor
/// was unnamed on every untrusted absence; this pins that the old keys stay dead.
#[test]
fn limiting_factor_ignores_keys_the_server_never_sends() {
    let outcome = unwrap_tool_result(
        &json!({
            "content": [{
                "type": "text",
                "text": json!({
                    "results": [],
                    "_kin": { "envelope_version": 2, "runtime": "repo-daemon" },
                    "negative": {
                        "safe_to_conclude_absent": false,
                        "limiting_factor": "python bodies are not indexed",
                        "reason": "x",
                        "why": "y",
                        "explanation": "z",
                        "missing_edge_classes": ["calls"]
                    }
                })
                .to_string()
            }],
            "isError": false
        }),
        1,
    );
    assert_eq!(outcome.limiting_factor(), None);
}

#[test]
fn retired_whole_artifact_read_never_enters_any_belt() {
    for label in [None, Some("legacy")] {
        let belt = Belt::new(vec![
            kin_tool(0, "kin_artifact_read", label),
            kin_tool(0, "get_entity_source", label),
        ]);
        assert!(!belt.has_kin_tool("kin_artifact_read"));
        let name = format!("{}kin_artifact_read", belt::tool_prefix(label));
        assert!(matches!(belt.route(&name), Route::Refused(_)));
        assert!(belt.schema_for(&name).is_none());
        assert!(!serde_json::to_string(&belt.to_specs())
            .unwrap()
            .contains("kin_artifact_read"));
        assert!(belt.has_kin_tool("get_entity_source"));
    }
}

#[test]
fn retired_file_catalogs_never_enter_a_belt_or_escape_through_dispatchers() {
    for label in [None, Some("legacy")] {
        let tools = [
            "kin_artifact_list",
            "list_file_entities",
            "kin_tool_call",
            "kin",
            "get_entity_source",
        ]
        .into_iter()
        .map(|name| kin_tool(0, name, label))
        .collect();
        let belt = Belt::new(tools);
        for retired in ["kin_artifact_list", "list_file_entities"] {
            assert!(!belt.has_kin_tool(retired));
            let exposed = format!("{}{retired}", belt::tool_prefix(label));
            assert!(!belt.names().contains(&exposed));
            assert!(belt.schema_for(&exposed).is_none());
            assert!(matches!(belt.route(&exposed), Route::Refused(_)));
            assert!(matches!(belt.route(retired), Route::Refused(_)));
            for (dispatcher, arguments) in [
                ("kin_tool_call", json!({"tool":retired,"arguments":{}})),
                ("kin", json!({"command":retired,"args":{}})),
                ("kin", json!({"command":format!("kin {retired}"),"args":{}})),
                (
                    "kin",
                    json!({"command":"call","args":{"tool":retired,"arguments":{}}}),
                ),
                (
                    "kin",
                    json!({"command":format!(" KIN {} ", retired.to_uppercase().replace('_', "-")),"args":{}}),
                ),
                (
                    "kin",
                    json!({"command":"KIN CALL","args":{"tool":format!("kin {}", retired.replace('_', "   ")),"arguments":{}}}),
                ),
                (
                    "kin",
                    json!({"command":"describe","args":{"command":retired}}),
                ),
            ] {
                let result = belt.route_call(
                    &format!("{}{dispatcher}", belt::tool_prefix(label)),
                    &arguments,
                );
                assert!(matches!(result.route, Route::Refused(_)), "{result:?}");
                assert_eq!(result.arguments, arguments);
            }
        }
        assert!(belt.has_kin_tool("get_entity_source"));
        let result = belt.route_call(
            &format!("{}kin_tool_call", belt::tool_prefix(label)),
            &json!({"tool":"get_entity_source","arguments":{"entity_id":"e1"}}),
        );
        assert!(matches!(result.route, Route::Kin { .. }));
    }
}
