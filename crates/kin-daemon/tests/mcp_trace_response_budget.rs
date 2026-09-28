// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Trace response pages preserve the complete bounded semantic walk. Each raw
//! page fits its byte ceiling, survives stdio finalization unchanged and stays
//! non-certifying until callers reconstruct all semantic records and readings.
//! Graph fanout, provenance and spine limits remain independent of page size.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kin_daemon::DaemonState;
use kin_mcp::budget::{
    ResponseBudget, RESPONSE_DEFAULT_MAX_CHARS, RESPONSE_MAX_MAX_CHARS, RESPONSE_MIN_MAX_CHARS,
};
use kin_mcp::envelope::{finalize_bounded, Envelope};
use kin_mcp::{ContentBlock, ToolCallResult};
use serde_json::{json, Value};
use tower::ServiceExt;

#[path = "support/trace_pages.rs"]
mod trace_page_test_support;
use trace_page_test_support::TraceAssembly;

const TOOL: &str = "trace_data_flow";

/// Steps the fixture walk reaches: `entry`, then `hop_59` down to `hop_53`.
const WALK_STEPS: usize = 8;

/// Owners that share the member name `get`, so `target: "get"` is ambiguous.
const OWNERS: usize = 40;

/// One linear chain, deep enough that a small budget has to cut it. The last
/// eight hops and the focal carry a hundred optional parameters each, so the
/// walk's records are larger than a 12,000-character reply can carry whole.
fn chain_source() -> String {
    let params: Vec<String> = (0..100).map(|index| format!("a{index}=0")).collect();
    let params = params.join(", ");
    let mut lines = vec![
        "def hop_0(value):".to_string(),
        "    \"\"\"The base of the chain.\"\"\"".to_string(),
        "    return value".to_string(),
    ];
    for index in 1..60 {
        let extra = if index >= 52 {
            format!(", {params}")
        } else {
            String::new()
        };
        lines.push(String::new());
        lines.push(String::new());
        lines.push(format!("def hop_{index}(value{extra}):"));
        lines.push(
            "    \"\"\"A hop carrying enough text to cost the budget real characters.\"\"\""
                .to_string(),
        );
        lines.push(format!("    return hop_{}(value) + {index}", index - 1));
    }
    lines.push(String::new());
    lines.push(String::new());
    lines.push(format!("def entry(value, {params}):"));
    lines.push("    \"\"\"The focal the deep walk starts from.\"\"\"".to_string());
    lines.push("    return hop_59(value)".to_string());
    lines.push(String::new());
    lines.join("\n")
}

/// Forty classes whose member `get` shares one name, and a short walk that
/// reaches one of them, so a `target` of `get` names forty candidates.
fn owners_source() -> String {
    let params: Vec<String> = (0..60).map(|index| format!("a{index}=0")).collect();
    let params = params.join(", ");
    let mut source = String::new();
    for owner in 0..OWNERS {
        source.push_str(&format!(
            "class Owner{owner:02}:\n    def get(self, {params}):\n        return a0\n\n\n"
        ));
    }
    source.push_str(
        "def leaf(value):\n    return value\n\n\n\
         def middle(value):\n    return Owner00().get() + leaf(value)\n\n\n\
         def start(value):\n    return middle(value)\n",
    );
    source
}

/// A root over five branches of five leaves each: thirty short steps. Their
/// pretty rendering outweighs their compact one by more than the envelope does,
/// so a walk the in-process arm cuts in pretty bytes can fit its budget once
/// the envelope pass renders it compact. `fork` calls two of the branches, so
/// a walk from it is clipped beneath the focal and never at it.
fn tree_source() -> String {
    let mut source = String::new();
    for branch in 0..5 {
        for leaf in 0..5 {
            source.push_str(&format!(
                "def leaf_{branch}_{leaf}(value):\n    return value\n\n\n"
            ));
        }
        let calls: Vec<String> = (0..5)
            .map(|leaf| format!("leaf_{branch}_{leaf}(value)"))
            .collect();
        source.push_str(&format!(
            "def branch_{branch}(value):\n    return {}\n\n\n",
            calls.join(" + ")
        ));
    }
    let calls: Vec<String> = (0..5)
        .map(|branch| format!("branch_{branch}(value)"))
        .collect();
    source.push_str(&format!(
        "def root(value):\n    return {}\n",
        calls.join(" + ")
    ));
    source.push_str("\n\ndef fork(value):\n    return branch_0(value) + branch_1(value)\n");
    source
}

/// Steps a walk from `padded_entry` reaches: `padded_7` down to `padded_0`.
const PADDED_STEPS: usize = 8;

/// A chain whose every function carries a long docstring and a short
/// signature, so its bodies outweigh everything else the walk and the envelope
/// write about it. A walk that sheds them fits a budget many kilobytes below
/// the whole walk, which is the room a cut the walk makes alone needs on the
/// daemon route, where an explicit `max_chars` reserves none for the envelope.
fn padded_source() -> String {
    let padding = "This hop carries its body's weight. ".repeat(60);
    let mut source = String::new();
    for index in 0..PADDED_STEPS {
        let next = if index == 0 {
            "value".to_string()
        } else {
            format!("padded_{}(value) + {index}", index - 1)
        };
        source.push_str(&format!(
            "def padded_{index}(value):\n    \"\"\"{padding}\"\"\"\n    return {next}\n\n\n"
        ));
    }
    source.push_str(&format!(
        "def padded_entry(value):\n    \"\"\"{padding}\"\"\"\n    return padded_{}(value)\n",
        PADDED_STEPS - 1
    ));
    source
}

/// A JavaScript hub over five branches of five leaves, whose leaves call into
/// a module the repository does not hold. A walk from `route_hub` at a cap of
/// three continues beneath clipped nodes, and a question naming `dispatchRemote`,
/// a binding the file imports from that module and calls directly, makes the
/// daemon route add its outside-graph block after the walk has fit. A call
/// through a receiver such as `Channel.send` records no external target, so it
/// would not. The
/// function is not named after its file, so the focal cannot resolve to the
/// file's module entity instead.
fn questioned_hub_source() -> String {
    let mut source = String::from("var dispatchRemote = require('external-wire');\n");
    source.push_str("function wire(value) { return dispatchRemote(value); }\n");
    for branch in 0..5 {
        let mut leaves = Vec::new();
        for leaf in 0..5 {
            source.push_str(&format!(
                "function leaf_{branch}_{leaf}(value) {{ return wire(value) + {leaf}; }}\n"
            ));
            leaves.push(format!("leaf_{branch}_{leaf}(value)"));
        }
        source.push_str(&format!(
            "function branch_{branch}(value) {{ return {}; }}\n",
            leaves.join(" + ")
        ));
    }
    let branches: Vec<String> = (0..5)
        .map(|branch| format!("branch_{branch}(value)"))
        .collect();
    source.push_str(&format!(
        "function route_hub(value) {{ return {}; }}\nmodule.exports = route_hub;\n",
        branches.join(" + ")
    ));
    source
}

/// Pin the daemon supervisor to a scratch registry, so nothing here reads or
/// writes the registry of the machine running the test.
fn install_scratch_registry() {
    static REGISTRY: OnceLock<std::path::PathBuf> = OnceLock::new();
    let path = REGISTRY.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "kin-trace-budget-registry-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&path)
            .unwrap();
        path
    });
    kin_core::test_env::install_process_wide("KIN_REGISTRY_PATH", path);
}

async fn post(state: &Arc<DaemonState>, uri: &str, body: Value) -> (StatusCode, String) {
    let response = kin_daemon::api::router(Arc::clone(state))
        .oneshot(
            Request::post(uri)
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// One call to the daemon's `/mcp/tools/call`, the route the stdio server
/// forwards every graph tool to.
async fn daemon_mcp(state: &Arc<DaemonState>, name: &str, arguments: &Value) -> ToolCallResult {
    let (status, body) = post(
        state,
        "/mcp/tools/call",
        json!({ "name": name, "arguments": arguments }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

fn text(result: &ToolCallResult) -> &str {
    let ContentBlock::Text { text } = result
        .content
        .first()
        .expect("a tool result carries a content block");
    text
}

fn payload(result: &ToolCallResult) -> Value {
    serde_json::from_str(text(result)).expect("a tool result payload is JSON")
}

fn arguments(value: &Value) -> HashMap<String, Value> {
    serde_json::from_value(value.clone()).unwrap()
}

/// The answer a stdio client receives: the daemon's result, then the envelope
/// pass `kin mcp start` applies under the budget read from the same arguments.
async fn served_page(
    state: &Arc<DaemonState>,
    arguments_json: &Value,
) -> (ToolCallResult, ToolCallResult) {
    let daemon = daemon_mcp(state, TOOL, arguments_json).await;
    let budget = ResponseBudget::from_arguments(&arguments(arguments_json));
    let client = finalize_bounded(daemon.clone(), Envelope::daemon(), TOOL, &budget);
    (daemon, client)
}

async fn served(state: &Arc<DaemonState>, query: &Value) -> (ToolCallResult, ToolCallResult) {
    let mut args = query.clone();
    let ceiling = ResponseBudget::from_arguments(&arguments(query)).max_chars;
    let mut assembly = TraceAssembly::default();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let (daemon, client) = served_page(state, &args).await;
        if client.is_error == Some(true) {
            return (daemon, client);
        }
        assert_eq!(
            text(&daemon),
            text(&client),
            "stdio must not mutate a frozen page"
        );
        let page = payload(&client);
        assert_eq!(page["_kin"]["page"]["version"], 1);
        if page["_kin"]["page"]["complete"] == true {
            assert!(text(&client).len() <= ceiling);
            assert_eq!(
                page["_kin"]["response"]["chars_after_budget"],
                text(&client).len()
            );
            return (daemon, client);
        }
        assembly.add(&page, text(&client), ceiling);
        if let Some(cursor) = page["next_cursor"].as_str() {
            assert!(seen.insert(cursor.to_string()), "cursor must advance");
            assert!(seen.len() < 10000);
            args["cursor"] = json!(cursor);
        } else {
            let result = ToolCallResult::text(assembly.finish().to_string());
            return (result.clone(), result);
        }
    }
}

fn step_ids(payload: &Value) -> Vec<String> {
    payload["chain"]
        .as_array()
        .unwrap_or_else(|| panic!("the answer carries a chain: {payload}"))
        .iter()
        .map(|step| step["entity_id"].as_str().unwrap_or_default().to_string())
        .collect()
}

async fn fixture() -> (tempfile::TempDir, Arc<DaemonState>) {
    fixture_with(&[
        ("src/chain.py", chain_source()),
        ("src/owners.py", owners_source()),
        ("src/tree.py", tree_source()),
    ])
    .await
}

/// Admit a legacy source fixture through conversion before semantic queries.
/// File creation is fixture preparation, never an agent transaction operation.
async fn fixture_with(sources: &[(&str, String)]) -> (tempfile::TempDir, Arc<DaemonState>) {
    install_scratch_registry();
    let dir = tempfile::tempdir().unwrap();
    for (path, body) in sources {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
    for args in [
        vec!["init", "--quiet"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Trace fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-s",
            "--quiet",
            "-m",
            "Seed conversion fixture",
        ],
    ] {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture Git: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let layout = kin_core::init_from_git(dir.path()).unwrap().layout;
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    (dir, state)
}

fn walk_with(budget: Option<(&str, usize)>) -> Value {
    let mut walk = json!({
        "focal": "entry",
        "depth": 8,
        "direction": "calls",
        "limit_per_step": 25,
        "include_body": false,
    });
    if let Some((key, value)) = budget {
        walk[key] = json!(value);
    }
    walk
}

#[tokio::test]
async fn mcp_trace_pages_fit_the_floor_and_preserve_ambiguity() {
    let (_dir, state) = fixture().await;
    let (_, whole) = served(
        &state,
        &walk_with(Some(("max_chars", RESPONSE_MAX_MAX_CHARS))),
    )
    .await;
    let expected = payload(&whole)["chain"].clone();
    for ceiling in [
        0,
        RESPONSE_MIN_MAX_CHARS - 1,
        RESPONSE_MIN_MAX_CHARS,
        6000,
        12000,
        RESPONSE_DEFAULT_MAX_CHARS,
    ] {
        for key in ["max_chars", "max_response_chars"] {
            let query = walk_with(Some((key, ceiling)));
            let (_, result) = served(&state, &query).await;
            assert_ne!(result.is_error, Some(true), "{}", text(&result));
            assert_eq!(payload(&result)["chain"], expected);
        }
    }
    let query = walk_with(Some(("max_response_chars", RESPONSE_MIN_MAX_CHARS)));
    let (daemon, _) = served_page(&state, &query).await;
    let (status, body) = post(&state, "/commands/trace-data-flow", query).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let command: Value = serde_json::from_str(&body).unwrap();
    assert!(body.len() <= RESPONSE_MIN_MAX_CHARS);
    assert_eq!(command["chain"], payload(&daemon)["chain"]);
    assert_eq!(
        command["record_fragment"],
        payload(&daemon)["record_fragment"]
    );
    for query in [
        json!({"focal":"get", "include_body":false, "max_chars":2000}),
        json!({"focal":"start", "target":"get", "direction":"calls", "depth":4,
               "include_body":false, "max_chars":2000}),
    ] {
        let (_, result) = served(&state, &query).await;
        assert_ne!(result.is_error, Some(true), "{}", text(&result));
        let answer = payload(&result);
        let focal_ambiguous = query.get("target").is_none();
        let listing = if focal_ambiguous {
            assert_eq!(answer["ambiguous_focal"], true);
            assert!(answer["chain"].as_array().is_none_or(Vec::is_empty));
            for selected in ["focal", "focal_entity", "focal_id", "body", "source_base"] {
                assert!(
                    answer.get(selected).is_none(),
                    "an ambiguous focal selected {selected}: {answer}"
                );
            }
            &answer
        } else {
            // A successful unselected target is disclosed under target_ambiguity;
            // ambiguous_target was the legacy budget-refusal representation.
            assert!(answer["target_ambiguity"].is_object());
            assert!(answer.get("target_name").is_none());
            assert!(!answer["chain"].as_array().unwrap().is_empty());
            assert!(answer["degradations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["component"] == "target_reachability"
                    && entry["reason"] == "target_ambiguous"));
            &answer["target_ambiguity"]
        };
        assert_eq!(listing["candidate_count"], OWNERS);
        assert_eq!(listing["resolution"], "shared_member_name");
        assert_eq!(listing["omitted_candidates"].as_u64().unwrap_or(0), 0);
        assert_eq!(listing["candidates"].as_array().unwrap().len(), OWNERS);
        if focal_ambiguous {
            // No focal was selected and no chain was queried, so the full
            // answer makes no absence claim. Its verdict still qualifies the
            // ambiguity, independently of each page's non-certifying guard.
            assert!(answer.get("negative").is_none());
        } else {
            assert_eq!(answer["negative"]["safe_to_conclude_absent"], false);
        }
        assert_eq!(answer["_kin"]["verdict"]["safe_to_conclude_absent"], false);
        assert_eq!(answer["_kin"]["verdict"]["state"], "inconclusive");
        assert_eq!(
            answer["_kin"]["verdict"]["inputs"]["degradations"],
            "inconclusive"
        );
    }
    let (status, body) = post(
        &state,
        "/commands/trace-data-flow",
        json!({"focal":"no_such_focal_in_this_fixture"}),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(body.contains("no entity found matching"), "{body}");
    let mut belt_args = arguments(&walk_with(None));
    kin_mcp::agent_belt::apply_belt_defaults(TOOL, &mut belt_args);
    assert_eq!(
        belt_args.get("max_chars"),
        Some(&json!(kin_mcp::agent_belt::AGENT_CHAIN_RESPONSE_MAX_CHARS))
    );
    let (_, belt_page) = served_page(&state, &json!(belt_args)).await;
    assert_eq!(
        payload(&belt_page)["_kin"]["response"]["max_chars"],
        kin_mcp::agent_belt::AGENT_CHAIN_RESPONSE_MAX_CHARS
    );
    assert!(
        text(&belt_page).len()
            <= usize::try_from(kin_mcp::agent_belt::AGENT_CHAIN_RESPONSE_MAX_CHARS).unwrap()
    );
    let belt = kin_mcp::tools::served_tools_list(
        Some(&kin_mcp::tools::name_set(
            kin_mcp::tools::agent_default_tool_names(),
        )),
        true,
    );
    let belt_trace = belt.tools.iter().find(|tool| tool.name == TOOL).unwrap();
    assert_eq!(
        belt_trace.input_schema["properties"]["max_chars"]["default"],
        kin_mcp::agent_belt::AGENT_CHAIN_RESPONSE_MAX_CHARS
    );
    assert!(
        belt_trace.input_schema["properties"]["max_chars"]["description"]
            .as_str()
            .unwrap()
            .starts_with("Hard")
    );
    let listing = kin_mcp::tools::tool_definitions();
    let trace = listing.tools.iter().find(|tool| tool.name == TOOL).unwrap();
    for key in ["max_response_chars", "max_chars"] {
        let property = &trace.input_schema["properties"][key];
        assert_eq!(property["minimum"], RESPONSE_MIN_MAX_CHARS);
        assert_eq!(property["default"], RESPONSE_DEFAULT_MAX_CHARS);
        assert_eq!(property["maximum"], RESPONSE_MAX_MAX_CHARS);
    }
    assert_eq!(trace.input_schema["properties"]["cursor"]["maxLength"], 256);
    assert!(
        trace.input_schema["properties"]["max_response_chars"]["description"]
            .as_str()
            .unwrap()
            .contains("Hard")
    );
}

/// Page ceilings span the minimum and multiple complete-record page sizes.
const CUT_CEILINGS: [usize; 3] = [RESPONSE_MIN_MAX_CHARS, 6_000, 13_000];

/// Totals and terminal counters describe the complete reconstructed chain.
#[tokio::test]
async fn mcp_trace_step_counters_describe_the_reconstructed_chain() {
    let (_dir, state) = fixture().await;
    for ceiling in CUT_CEILINGS {
        let (_, result) = served(&state, &walk_with(Some(("max_chars", ceiling)))).await;
        let answer = payload(&result);
        assert_eq!(step_ids(&answer).len(), WALK_STEPS);
        assert_eq!(answer["total_steps"], WALK_STEPS);
        assert_eq!(answer["steps_omitted"].as_u64().unwrap_or(0), 0);
        assert!(chain_contradictions(&format!("{ceiling}"), &answer).is_empty());
    }
}

/// The floor emits a qualified bounded page, unchanged by stdio finalization.
#[tokio::test]
async fn mcp_trace_raw_page_accounting_is_bounded_and_stdio_preserves_it() {
    let (_dir, state) = fixture().await;
    let query = walk_with(Some(("max_chars", RESPONSE_MIN_MAX_CHARS)));
    let (daemon, client) = served_page(&state, &query).await;
    assert_eq!(text(&daemon), text(&client));
    let page = payload(&client);
    assert!(text(&client).len() <= RESPONSE_MIN_MAX_CHARS);
    assert_eq!(page["_kin"]["response"]["bounded"], true);
    assert!(page["next_cursor"].is_string());
    assert_eq!(page["negative"]["safe_to_conclude_absent"], false);
    assert_eq!(page["_kin"]["verdict"]["state"], "inconclusive");
}

/// How many steps the walk's own cut dropped, as its `response_budget`
/// disclosure counts them: none for a cut that shed only bodies, and `None`
/// when the walk made no cut at all.
///
/// Read from the disclosure's words because they are what a reader is given.
/// The walk names its cut `steps_omitted` or `bodies_omitted`, and the
/// envelope pass names its own `response_bounded`, so each pass's count is
/// read from the entry that pass wrote.
fn walk_cut_steps(answer: &Value) -> Option<u64> {
    let entry = walk_cut_entry(answer)?;
    if entry["reason"] == "bodies_omitted" {
        return Some(0);
    }
    let detail = entry["detail"].as_str().unwrap_or_default();
    detail.match_indices(" step").find_map(|(at, _)| {
        let digits: String = detail[..at]
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<Vec<char>>()
            .into_iter()
            .rev()
            .collect();
        digits.parse::<u64>().ok()
    })
}

/// The walk's own `response_budget` disclosure of the cut it made, if it made
/// one. The envelope pass discloses its own cut as `response_bounded`.
fn walk_cut_entry(answer: &Value) -> Option<&Value> {
    answer["degradations"].as_array()?.iter().find(|entry| {
        entry["component"] == "response_budget"
            && (entry["reason"] == "steps_omitted" || entry["reason"] == "bodies_omitted")
    })
}

/// Whether the steps each pass says it cut add up to what the reply counts:
/// the walk's own count plus `chain_withheld` is `steps_omitted`, which is
/// `elisions.chain.elided`. `None` when they agree.
fn step_sum_contradiction(label: &str, answer: &Value) -> Option<String> {
    let walk = walk_cut_steps(answer).unwrap_or(0);
    let withheld = answer["chain_withheld"].as_u64().unwrap_or(0);
    let omitted = answer["steps_omitted"].as_u64().unwrap_or(0);
    let elided = answer["elisions"]["chain"]["elided"].as_u64().unwrap_or(0);
    (walk + withheld != omitted || omitted != elided).then(|| {
        format!(
            "{label}: the walk says it dropped {walk} step(s) and the envelope pass withheld \
             {withheld}, beside steps_omitted {omitted} and elisions.chain.elided {elided}"
        )
    })
}

/// Requested entity bodies and absolute parent/step identities survive every page.
#[tokio::test]
async fn mcp_trace_paging_preserves_requested_bodies_and_step_identity() {
    let (_dir, state) = fixture_with(&[("src/padded.py", padded_source())]).await;
    let mut wide = walk_with(Some(("max_chars", RESPONSE_MAX_MAX_CHARS)));
    wide["include_body"] = json!(true);
    wide["focal"] = json!("padded_entry");
    let (_, whole) = served(&state, &wide).await;
    let expected = payload(&whole);
    assert_eq!(expected["chain"].as_array().unwrap().len(), WALK_STEPS);
    assert!(expected["chain"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["body"].as_str().is_some_and(|body| body.len() > 2000)));
    for ceiling in [2000, 6000, 12000, 20000] {
        let mut query = wide.clone();
        query["max_chars"] = json!(ceiling);
        let (_, result) = served(&state, &query).await;
        let answer = payload(&result);
        assert_eq!(answer["chain"], expected["chain"]);
        assert_eq!(answer["focal"], expected["focal"]);
        assert_eq!(answer["steps_omitted"].as_u64().unwrap_or(0), 0);
        assert!(!answer["body_omitted"].as_bool().unwrap_or(false));
    }
}

/// The keys a trace reply counts its steps' terminals under, and the terminal
/// each counts, as both walks write them.
const TERMINAL_COUNTS: [(&str, &str); 5] = [
    ("terminal_external_steps", "external_reference"),
    ("terminal_annotation_steps", "type_annotation"),
    ("terminal_leaf_steps", "leaf"),
    ("terminal_bound_steps", "bound_reached"),
    ("terminal_coverage_gap_steps", "coverage_gap"),
];

/// Every count a trace reply keeps beside its chain that the chain it ships
/// contradicts, one line each.
fn chain_contradictions(label: &str, answer: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let chain = answer["chain"].as_array().cloned().unwrap_or_default();
    for (key, terminal) in TERMINAL_COUNTS {
        let shipped = chain
            .iter()
            .filter(|step| step["terminal"] == json!(terminal))
            .count();
        if answer[key].as_u64().unwrap_or(0) as usize != shipped {
            problems.push(format!(
                "{label}: {key} is {} and the chain ships {shipped} step(s) ending {terminal}",
                answer[key]
            ));
        }
    }
    let text = answer.to_string();
    for (at, _) in text.match_indices(" step(s) were omitted from the response") {
        let digits: String = text[..at]
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<Vec<char>>()
            .into_iter()
            .rev()
            .collect();
        if json!(digits.parse::<u64>().ok()) != answer["steps_omitted"] {
            problems.push(format!(
                "{label}: a qualification says {digits} step(s) were omitted and steps_omitted \
                 is {}",
                answer["steps_omitted"]
            ));
        }
    }
    // The negative counts the rows this reply ships.
    if let Some(count) = answer["negative"]["result_count"].as_u64() {
        if count as usize != chain.len() {
            problems.push(format!(
                "{label}: negative.result_count is {count} and the chain ships {} step(s)",
                chain.len()
            ));
        }
    }
    // The walk's disclosure counts the walk's own cut, says so, and counts in
    // words a reader can take at face value; with the envelope pass's share,
    // it adds up to what the reply counts.
    if let Some(detail) = walk_cut_entry(answer).and_then(|entry| entry["detail"].as_str()) {
        if !detail.starts_with("the walk ") {
            problems.push(format!(
                "{label}: the walk's cut disclosure does not say whose cut it counts: {detail}"
            ));
        }
        for noun in ["steps", "inlined bodies"] {
            if detail.contains(&format!(" 1 {noun}")) {
                problems.push(format!(
                    "{label}: the walk's cut disclosure says 1 {noun}: {detail}"
                ));
            }
        }
    }
    problems.extend(step_sum_contradiction(label, answer));
    println!(
        "{label}: chain {}, chain_withheld {}, steps_omitted {}, terminal_bound_steps {}, \
         spine_clipped_steps {}",
        chain.len(),
        answer["chain_withheld"],
        answer["steps_omitted"],
        answer["terminal_bound_steps"],
        answer["spine_clipped_steps"],
    );
    problems
}

/// Nothing a trace reply counts beside its chain may contradict the chain it
/// ships, whichever pass cut it.
///
/// The walk counts its steps' terminals from the chain it hands over, and the
/// negative it is qualified with counts the steps omitted from the response.
/// The envelope pass then cuts that chain again when the reply and its envelope
/// do not fit. Measured on this fixture before the counts were restated after
/// that cut: at 12,000 bytes the reply kept `terminal_bound_steps: 1` beside a
/// chain whose bound step the cut had taken, and a tree cut at 5,000 said "9
/// step(s) were omitted from the response" beside `steps_omitted: 11`.
///
/// The negative's `result_count` is counted before the envelope pass too, and
/// a reply that pass cut to two steps with bodies said `result_count: 7`. Each
/// pass discloses its own cut, so the walk's disclosure says it counts the
/// walk's, and its count and `chain_withheld` add up to `steps_omitted`.
#[tokio::test]
async fn mcp_trace_counts_beside_the_chain_describe_the_chain_that_ships() {
    let (_dir, state) = fixture().await;
    let mut problems: Vec<String> = Vec::new();
    for ceiling in [
        RESPONSE_MIN_MAX_CHARS,
        6_000,
        12_000,
        RESPONSE_DEFAULT_MAX_CHARS,
    ] {
        let (_, client) = served(&state, &walk_with(Some(("max_chars", ceiling)))).await;
        problems.extend(chain_contradictions(
            &format!("entry at {ceiling}"),
            &payload(&client),
        ));
    }
    for ceiling in [
        3_000usize,
        4_000,
        5_000,
        6_000,
        8_000,
        10_000,
        RESPONSE_DEFAULT_MAX_CHARS,
    ] {
        let walk = json!({
            "focal": "root", "depth": 2, "direction": "calls", "limit_per_step": 3,
            "include_body": false, "max_chars": ceiling,
        });
        let (_, client) = served(&state, &walk).await;
        problems.extend(chain_contradictions(
            &format!("tree, three per step, daemon route at {ceiling}"),
            &payload(&client),
        ));
        let args = arguments(&walk);
        let raw = kin_mcp::handlers::entities::handle_trace_data_flow(&args, state.graph.as_ref())
            .expect("the in-process walk answers");
        let client = finalize_bounded(
            raw,
            Envelope::offline(),
            TOOL,
            &ResponseBudget::from_arguments(&args),
        );
        problems.extend(chain_contradictions(
            &format!("tree, three per step, in-process at {ceiling}"),
            &payload(&client),
        ));
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// The in-process walk the hosted and offline routes serve walks under the
/// budget the envelope pass grades, read by the same rule: `max_chars` first,
/// then the older `max_response_chars`.
///
/// It read only the older spelling. A call passing `max_chars: 2000` walked
/// under the 45,000 default while the envelope cut the reply to 2,000, and the
/// payload's `max_response_chars: 45000` contradicted `_kin.response.max_chars:
/// 2000`. A focal or target several owners share was listed against the same
/// wrong number.
#[tokio::test]
async fn the_in_process_walk_reads_the_budget_the_envelope_grades() {
    let (_dir, state) = fixture().await;
    let in_process = |walk: &Value| {
        kin_mcp::handlers::entities::handle_trace_data_flow(&arguments(walk), state.graph.as_ref())
            .expect("the in-process walk answers")
    };
    let mut problems: Vec<String> = Vec::new();
    let mut both = walk_with(Some(("max_chars", 12_000)));
    both["max_response_chars"] = json!(RESPONSE_MIN_MAX_CHARS);
    for (label, walk) in [
        (
            "max_chars",
            walk_with(Some(("max_chars", RESPONSE_MIN_MAX_CHARS))),
        ),
        (
            "max_response_chars",
            walk_with(Some(("max_response_chars", RESPONSE_MIN_MAX_CHARS))),
        ),
        ("both spellings", both),
    ] {
        let raw = in_process(&walk);
        let walked = payload(&raw);
        let budget = ResponseBudget::from_arguments(&arguments(&walk));
        let client = finalize_bounded(raw.clone(), Envelope::offline(), TOOL, &budget);
        let graded = payload(&client)["_kin"]["response"]["max_chars"].clone();
        println!(
            "{label}: the walk's max_response_chars {}, steps_omitted {}, raw {} bytes; \
             _kin.response.max_chars {graded}",
            walked["max_response_chars"],
            walked["steps_omitted"],
            text(&raw).len()
        );
        if walked["max_response_chars"] != graded {
            problems.push(format!(
                "{label}: the walk ran under max_response_chars {} and the envelope graded \
                 max_chars {graded}",
                walked["max_response_chars"]
            ));
        }
    }
    for (label, walk) in [
        (
            "shared focal",
            json!({ "focal": "get", "depth": 4, "direction": "calls", "include_body": false,
                    "max_chars": RESPONSE_MIN_MAX_CHARS }),
        ),
        (
            "shared target",
            json!({ "focal": "start", "target": "get", "depth": 4, "direction": "calls",
                    "include_body": false, "max_chars": RESPONSE_MIN_MAX_CHARS }),
        ),
    ] {
        let raw = in_process(&walk);
        println!(
            "{label}: in-process is_error {:?}, {} bytes",
            raw.is_error,
            text(&raw).len()
        );
        if raw.is_error != Some(true) && text(&raw).len() > RESPONSE_MIN_MAX_CHARS {
            problems.push(format!(
                "{label}: the in-process reply is {} bytes against a {RESPONSE_MIN_MAX_CHARS}-byte \
                 max_chars and is not refused",
                text(&raw).len()
            ));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// Both byte-budget spellings and their precedence govern the exact emitted page.
#[tokio::test]
async fn the_daemon_route_pages_under_the_budget_the_envelope_grades() {
    let (_dir, state) = fixture().await;
    let mut both = walk_with(Some(("max_chars", 12000)));
    both["max_response_chars"] = json!(2000);
    for query in [
        walk_with(Some(("max_chars", 6000))),
        walk_with(Some(("max_response_chars", 6000))),
        both,
    ] {
        let expected = ResponseBudget::from_arguments(&arguments(&query)).max_chars;
        let (daemon, client) = served_page(&state, &query).await;
        assert_eq!(text(&daemon), text(&client));
        assert_eq!(payload(&client)["_kin"]["response"]["max_chars"], expected);
        assert!(text(&client).len() <= expected);
        let (_, reconstructed) = served(&state, &query).await;
        assert_eq!(step_ids(&payload(&reconstructed)).len(), WALK_STEPS);
    }
}

/// The spine a walk reports, as `(clipped node, continued_below, dropped)` per
/// clip record, beside its count and its `fanout_cap` / `spine_clipped`
/// disclosure.
fn spine_report(walk: &Value) -> Value {
    let clips: Vec<Value> = walk["clipped_steps"]
        .as_array()
        .map(|clips| {
            clips
                .iter()
                .map(|clip| {
                    json!([
                        clip["entity_name"],
                        clip["continued_below"],
                        clip["dropped_callees"].as_u64().unwrap_or(0)
                            + clip["dropped_callers"].as_u64().unwrap_or(0),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();
    let disclosure = walk["degradations"].as_array().and_then(|entries| {
        entries
            .iter()
            .find(|entry| entry["component"] == "fanout_cap" && entry["reason"] == "spine_clipped")
            .map(|entry| json!([entry["detail"], entry["remediation"]]))
    });
    json!({
        "clips": clips,
        "spine_clipped_steps": walk["spine_clipped_steps"],
        "spine_dropped_crossing_file": walk["spine_dropped_crossing_file"],
        "disclosure": disclosure,
    })
}

/// Both walks report the same spine in the same words.
///
/// The CLI walk the daemon route serves and the in-process walk the hosted and
/// offline routes serve each record the clipped nodes a chain continues
/// beneath, and each used to write its own sentence about them. On this
/// fixture the two drifted apart: the CLI walk's carried runs of spaces and
/// named `branch_2` as the widest node, while the in-process walk's named
/// `root` and did not count what the cap dropped. Both now take the sentence
/// from one producer, and this holds them to it, on walks the budget does not
/// cut.
#[tokio::test]
async fn both_trace_walkers_report_spine_clipping() {
    let (_dir, state) = fixture().await;
    let mut problems: Vec<String> = Vec::new();
    for (focal, limit) in [("root", 3), ("root", 2), ("branch_0", 3)] {
        let walk = json!({
            "focal": focal, "depth": 2, "direction": "calls", "limit_per_step": limit,
            "include_body": false, "max_chars": RESPONSE_DEFAULT_MAX_CHARS,
        });
        let cli = payload(&daemon_mcp(&state, TOOL, &walk).await);
        let in_process = payload(
            &kin_mcp::handlers::entities::handle_trace_data_flow(
                &arguments(&walk),
                state.graph.as_ref(),
            )
            .expect("the in-process walk answers"),
        );
        let (cli, in_process) = (spine_report(&cli), spine_report(&in_process));
        println!("{focal} at limit {limit}: {cli}");
        if cli["clips"].as_array().is_none_or(Vec::is_empty) {
            problems.push(format!(
                "{focal} at limit {limit}: the cap clipped nothing, so this compares nothing"
            ));
        }
        if cli != in_process {
            problems.push(format!(
                "{focal} at limit {limit}: the CLI walk reports {cli} and the in-process walk \
                 {in_process}"
            ));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// Everything a trace reply says about the clipped nodes its chain continues
/// beneath that the chain it ships contradicts, one line each.
///
/// A node is on the shipped spine when it ships, the cap cut its fan-out, and
/// a shipped step names it as parent. A chain step says the cap cut it with
/// `fanout_truncated`, and the focal, which has no step, with its clip record.
/// `walked_crossing` is how many of each clipped node's drops crossed a file,
/// as the uncut walk's clip records say: a cut that withholds a node's record
/// does not change what that node dropped.
fn spine_contradictions(
    label: &str,
    answer: &Value,
    walked_crossing: &std::collections::BTreeMap<String, u64>,
) -> Vec<String> {
    let mut problems = Vec::new();
    let chain = answer["chain"].as_array().cloned().unwrap_or_default();
    let clips = answer["clipped_steps"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let parents: std::collections::BTreeSet<u64> = chain
        .iter()
        .filter_map(|step| step["parent_step"].as_u64())
        .collect();
    let mut spine: Vec<String> = Vec::new();
    if parents.contains(&0) {
        if let Some(focal) = clips.iter().find(|clip| clip["step"] == json!(0)) {
            spine.push(
                focal["entity_name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
        }
    }
    for step in &chain {
        let beneath = step["step"]
            .as_u64()
            .is_some_and(|id| parents.contains(&id));
        if beneath && step["fanout_truncated"] == json!(true) {
            spine.push(step["entity_name"].as_str().unwrap_or_default().to_string());
        }
    }
    let reported = answer["spine_clipped_steps"].as_u64().unwrap_or(0) as usize;
    if reported != spine.len() {
        problems.push(format!(
            "{label}: spine_clipped_steps is {reported} and the chain continues beneath {} \
             clipped node(s) {spine:?}",
            spine.len()
        ));
    }
    for clip in &clips {
        let beneath = clip["step"]
            .as_u64()
            .is_some_and(|step| parents.contains(&step));
        if clip["continued_below"] != json!(beneath) {
            problems.push(format!(
                "{label}: the clip at step {} says continued_below {} and a shipped step sits \
                 beneath it: {beneath}",
                clip["step"], clip["continued_below"]
            ));
        }
    }
    let crossing: u64 = spine
        .iter()
        .map(|name| walked_crossing.get(name).copied().unwrap_or(0))
        .sum();
    if answer["spine_dropped_crossing_file"].as_u64().unwrap_or(0) != crossing {
        problems.push(format!(
            "{label}: spine_dropped_crossing_file is {} and the shipped spine's nodes dropped \
             {crossing} crossing a file",
            answer["spine_dropped_crossing_file"]
        ));
    }
    // The number after `prefix` in `text`, and the quoted name after `quote`.
    let number_after = |text: &str, prefix: &str| {
        text.find(prefix).and_then(|at| {
            text[at + prefix.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<usize>()
                .ok()
        })
    };
    let name_after = |text: &str, quote: &str| {
        text.find(quote).and_then(|at| {
            let rest = &text[at + quote.len()..];
            rest.find('\'').map(|end| rest[..end].to_string())
        })
    };
    let disclosure = answer["degradations"].as_array().and_then(|entries| {
        entries
            .iter()
            .find(|entry| {
                entry["component"] == json!("fanout_cap")
                    && entry["reason"] == json!("spine_clipped")
            })
            .cloned()
    });
    match (&disclosure, spine.is_empty()) {
        (Some(_), true) => problems.push(format!(
            "{label}: a spine disclosure on a chain that continues beneath no clipped node"
        )),
        (None, false) => problems.push(format!(
            "{label}: no spine disclosure while the chain continues beneath {spine:?}"
        )),
        _ => {}
    }
    if let Some(disclosure) = &disclosure {
        let detail = disclosure["detail"].as_str().unwrap_or_default();
        let remediation = disclosure["remediation"].as_str().unwrap_or_default();
        if detail.contains("  ") {
            problems.push(format!(
                "{label}: the spine disclosure carries a run of spaces: {detail}"
            ));
        }
        if let Some(count) = number_after(detail, "the walk continued beneath ") {
            if count != spine.len() {
                problems.push(format!(
                    "{label}: the spine disclosure counts {count} node(s) and the chain \
                     continues beneath {}",
                    spine.len()
                ));
            }
        }
        for named in [
            name_after(detail, "the widest was '"),
            name_after(remediation, "re-query '"),
            name_after(remediation, "re-query of '"),
        ]
        .into_iter()
        .flatten()
        {
            if !spine.contains(&named) {
                problems.push(format!(
                    "{label}: the spine disclosure names '{named}', which the shipped chain \
                     does not continue beneath {spine:?}"
                ));
            }
        }
    }
    let reason = answer["negative"]["trust_reason"]
        .as_str()
        .unwrap_or_default();
    match number_after(reason, "trace_spine_clipped: the walk continued beneath ") {
        Some(count) if count != spine.len() => problems.push(format!(
            "{label}: the negative's clause counts {count} node(s) and the chain continues \
             beneath {}",
            spine.len()
        )),
        None if !spine.is_empty() => problems.push(format!(
            "{label}: the negative has no spine clause while the chain continues beneath \
             {spine:?}"
        )),
        _ => {}
    }
    if spine.is_empty() {
        for (block, value) in [
            (
                "_kin.verdict.limiting_factor",
                answer["_kin"]["verdict"]["limiting_factor"].to_string(),
            ),
            (
                "negative.degraded_signals",
                answer["negative"]["degraded_signals"].to_string(),
            ),
            ("negative.advice", answer["negative"]["advice"].to_string()),
        ] {
            if value.contains("spine") {
                problems.push(format!(
                    "{label}: {block} still names the spine the chain no longer has: {value}"
                ));
            }
        }
    }
    println!(
        "{label}: chain {}, shipped spine {spine:?}, spine_clipped_steps {}, disclosure {}",
        chain.len(),
        answer["spine_clipped_steps"],
        disclosure
            .as_ref()
            .map_or("none".to_string(), |disclosure| disclosure["detail"]
                .to_string()),
    );
    problems
}

/// What a trace reply says about the clipped nodes its chain continues beneath
/// describes the chain it ships, whichever pass cut it, and names no node the
/// cut took.
///
/// The walk writes the spine count, each clip record's `continued_below`, the
/// `fanout_cap` / `spine_clipped` disclosure and the negative's
/// `trace_spine_clipped` clause for the chain it hands over. Measured on this
/// fixture before they were restated after an envelope-pass cut: the daemon
/// route at 10,000 bytes shipped a one-step tree chain beside
/// `spine_clipped_steps: 4`, whose only spine node was the focal, and the
/// disclosure it kept came from the walk: its count and its widest node
/// described the chain before the cut. A walk from `fork`, whose focal the cap
/// never clipped, can be cut until no shipped node is on the spine at all, and
/// the whole disclosure then described a chain the reply no longer carried.
#[tokio::test]
async fn mcp_trace_spine_disclosure_describes_the_chain_that_ships() {
    let (_dir, state) = fixture().await;
    let mut problems: Vec<String> = Vec::new();
    // Whether the sweep reached the two cases this test exists for.
    let (mut spine_narrowed, mut spine_emptied) = (false, false);
    for focal in ["root", "fork"] {
        let mut walk_spine = 0usize;
        let mut walked_crossing: std::collections::BTreeMap<String, u64> = Default::default();
        for ceiling in [
            RESPONSE_DEFAULT_MAX_CHARS,
            3_000,
            4_000,
            5_000,
            6_000,
            8_000,
            10_000,
        ] {
            let walk = json!({
                "focal": focal, "depth": 2, "direction": "calls", "limit_per_step": 3,
                "include_body": false, "max_chars": ceiling,
            });
            let (_, client) = served(&state, &walk).await;
            let args = arguments(&walk);
            let raw =
                kin_mcp::handlers::entities::handle_trace_data_flow(&args, state.graph.as_ref())
                    .expect("the in-process walk answers");
            let in_process = finalize_bounded(
                raw,
                Envelope::offline(),
                TOOL,
                &ResponseBudget::from_arguments(&args),
            );
            for (route, result) in [("daemon route", &client), ("in-process", &in_process)] {
                let answer = payload(result);
                let label = format!("{focal}, {route} at {ceiling}");
                if ceiling == RESPONSE_DEFAULT_MAX_CHARS {
                    for clip in answer["clipped_steps"].as_array().into_iter().flatten() {
                        walked_crossing.insert(
                            clip["entity_name"].as_str().unwrap_or_default().to_string(),
                            clip["dropped_crossing_file"].as_u64().unwrap_or(0),
                        );
                    }
                }
                let found = spine_contradictions(&label, &answer, &walked_crossing);
                let shipped = answer["chain"].as_array().map_or(0, Vec::len);
                if ceiling == RESPONSE_DEFAULT_MAX_CHARS {
                    walk_spine = walk_spine
                        .max(answer["spine_clipped_steps"].as_u64().unwrap_or(0) as usize);
                } else if route == "in-process" && found.is_empty() && shipped > 0 {
                    let spine = answer["spine_clipped_steps"].as_u64().unwrap_or(0) as usize;
                    spine_narrowed |= spine > 0 && spine < walk_spine;
                    if spine == 0 && walk_spine > 0 {
                        spine_emptied = true;
                        // No spine is left, and the reply still says it was
                        // cut, so a hop it lacks is not read as one the walk
                        // looked for.
                        if answer["truncated"] != json!(true)
                            || answer["steps_omitted"].as_u64().unwrap_or(0) == 0
                            || answer["_kin"]["verdict"]["state"] == json!("authoritative")
                            || answer["negative"]["safe_to_conclude_absent"] == json!(true)
                        {
                            problems.push(format!(
                                "{label}: the cut took the whole spine and the reply no longer \
                                 says it was cut: truncated {}, steps_omitted {}, verdict {}, \
                                 safe_to_conclude_absent {}",
                                answer["truncated"],
                                answer["steps_omitted"],
                                answer["_kin"]["verdict"]["state"],
                                answer["negative"]["safe_to_conclude_absent"]
                            ));
                        }
                    }
                }
                problems.extend(found);
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert!(
        spine_narrowed,
        "no reply kept a smaller spine than its walk, so the restated count was never graded"
    );
    assert!(
        spine_emptied,
        "no reply lost its whole spine to a cut, so the withdrawal was never graded"
    );
}

/// When the envelope pass restates a reply's spine, every clipped node the
/// reply ships on it is read from its own clip record, so its crossing count is
/// known and `spine_dropped_crossing_file` is exact.
///
/// The restatement reads each node from the clip records the passes before it
/// handed over. The daemon route bounds a trace twice before the stdio envelope
/// pass bounds it again, and a pass withholds clip records before chain steps,
/// so a record an earlier pass withheld while its node still shipped on the
/// spine would reach the restatement with that count unknown. This drives the
/// daemon route across the walk's floor and the ceilings above it, and asserts
/// both that its own passes did withhold clip records somewhere and that no
/// shipped spine node ever reached the envelope pass without its record.
#[tokio::test]
async fn the_envelope_pass_reads_every_shipped_spine_nodes_clip_record() {
    let (_dir, state) = fixture().await;
    let mut problems: Vec<String> = Vec::new();
    let mut route_withheld_records = 0usize;
    let mut arms = 0usize;
    for focal in ["root", "fork", "branch_0"] {
        for limit in [2u64, 3] {
            let walk = |ceiling: usize| {
                json!({
                    "focal": focal, "depth": 2, "direction": "calls",
                    "limit_per_step": limit, "include_body": false, "max_chars": ceiling,
                })
            };
            // The clipped nodes, from the walk no budget cut.
            let (whole, _) = served(&state, &walk(RESPONSE_MAX_MAX_CHARS)).await;
            let clipped: std::collections::BTreeSet<u64> = payload(&whole)["clipped_steps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|clip| clip["step"].as_u64())
                .collect();
            for ceiling in [
                RESPONSE_MIN_MAX_CHARS,
                2_500,
                3_000,
                4_000,
                5_000,
                6_000,
                8_000,
                10_000,
                RESPONSE_DEFAULT_MAX_CHARS,
            ] {
                arms += 1;
                let label = format!("{focal} at limit {limit}, daemon route at {ceiling}");
                let (daemon, client) = served(&state, &walk(ceiling)).await;
                // What the envelope pass read: the reply the daemon route's
                // own passes handed over.
                let handed = payload(&daemon);
                if handed.get("clipped_steps_withheld").is_some() {
                    route_withheld_records += 1;
                }
                let recorded: std::collections::BTreeSet<u64> = handed["clipped_steps"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|clip| clip["step"].as_u64())
                    .collect();
                let answer = payload(&client);
                let chain = answer["chain"].as_array().cloned().unwrap_or_default();
                let parents: std::collections::BTreeSet<u64> = chain
                    .iter()
                    .filter_map(|step| step["parent_step"].as_u64())
                    .collect();
                let shipped: std::collections::BTreeSet<u64> = std::iter::once(0)
                    .chain(chain.iter().filter_map(|step| step["step"].as_u64()))
                    .collect();
                for node in clipped
                    .iter()
                    .filter(|node| shipped.contains(*node) && parents.contains(*node))
                {
                    if !recorded.contains(node) {
                        problems.push(format!(
                            "{label}: spine node at step {node} ships and its clip record did \
                             not reach the envelope pass: {handed}"
                        ));
                    }
                }
                println!(
                    "{label}: the route passes handed {} clip record(s), withheld {}; the reply \
                     ships {} step(s) and spine_clipped_steps {}",
                    recorded.len(),
                    handed["clipped_steps_withheld"],
                    chain.len(),
                    answer["spine_clipped_steps"]
                );
            }
        }
    }
    println!("{arms} arms; the route passes withheld clip records in {route_withheld_records}");
    assert!(
        route_withheld_records == 0,
        "pagination must preserve every clip record across {arms} arms"
    );
    assert!(problems.is_empty(), "{problems:#?}");
}

/// A spine node whose clip record an earlier pass withheld reaches the
/// envelope pass with its crossing count unknown, and the reply then marks
/// `spine_dropped_crossing_file` as a floor; a reply whose every spine record
/// arrived never does.
///
/// The daemon route adds its outside-graph block after the walk has fit
/// whenever a call carries a `question`, and re-fits the reply, which withholds
/// clip records before chain steps. The envelope pass then reads what is left.
/// This sweeps ceilings on a walk that carries such a question, and grades the
/// marker against what actually reached the envelope pass on every arm.
#[tokio::test]
async fn a_spine_crossing_count_the_envelope_pass_cannot_read_whole_is_marked_a_floor() {
    let (_dir, state) = fixture_with(&[("src/hub.js", questioned_hub_source())]).await;
    let walk = |ceiling: usize| {
        json!({
            "focal": "route_hub", "depth": 2, "direction": "calls", "limit_per_step": 3,
            "include_body": false, "max_chars": ceiling,
            "question": "where does dispatchRemote send the value",
        })
    };
    let (whole, _) = served(&state, &walk(RESPONSE_MAX_MAX_CHARS)).await;
    let whole = payload(&whole);
    let clipped: std::collections::BTreeSet<u64> = whole["clipped_steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|clip| clip["step"].as_u64())
        .collect();
    println!(
        "questioned hub: outside_graph {}, {} clip record(s), spine_clipped_steps {}",
        whole.get("outside_graph").is_some(),
        clipped.len(),
        whole["spine_clipped_steps"]
    );
    // The sweep grades nothing unless the walk clips its spine and the question
    // names a module the graph holds only as an outside reference.
    assert!(
        !clipped.is_empty(),
        "the questioned walk must clip its spine: {whole}"
    );
    assert!(
        whole.get("outside_graph").is_some(),
        "the question must name the module outside this graph: {whole}"
    );
    let mut problems: Vec<String> = Vec::new();
    let (mut arms, mut occurred, mut withheld_arms) = (0usize, 0usize, 0usize);
    for ceiling in (2_000..=12_000usize).step_by(250) {
        arms += 1;
        let label = format!("questioned hub at {ceiling}");
        let (daemon, client) = served(&state, &walk(ceiling)).await;
        let handed = payload(&daemon);
        let recorded: std::collections::BTreeSet<u64> = handed["clipped_steps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|clip| clip["step"].as_u64())
            .collect();
        let answer = payload(&client);
        let chain = answer["chain"].as_array().cloned().unwrap_or_default();
        let parents: std::collections::BTreeSet<u64> = chain
            .iter()
            .filter_map(|step| step["parent_step"].as_u64())
            .collect();
        let shipped: std::collections::BTreeSet<u64> = std::iter::once(0)
            .chain(chain.iter().filter_map(|step| step["step"].as_u64()))
            .collect();
        let unread = clipped
            .iter()
            .filter(|node| {
                shipped.contains(*node) && parents.contains(*node) && !recorded.contains(*node)
            })
            .count();
        let marked = answer["spine_dropped_crossing_file_is_floor"] == json!(true);
        occurred += usize::from(unread > 0);
        withheld_arms += usize::from(recorded.len() < clipped.len());
        if marked != (unread > 0) {
            problems.push(format!(
                "{label}: {unread} shipped spine node(s) reached the envelope pass without \
                 their clip record, and spine_dropped_crossing_file_is_floor is {}",
                answer["spine_dropped_crossing_file_is_floor"]
            ));
        }
        println!(
            "{label}: outside_graph {}, the route passes handed {} clip record(s) and withheld \
             {}; the reply ships {} step(s), spine_clipped_steps {}, unread spine records \
             {unread}, floor marker {}",
            handed.get("outside_graph").is_some(),
            recorded.len(),
            handed["clipped_steps_withheld"],
            chain.len(),
            answer["spine_clipped_steps"],
            answer["spine_dropped_crossing_file_is_floor"]
        );
    }
    println!(
        "{arms} arms; the route passes withheld clip records in {withheld_arms}; the state \
         occurred in {occurred}"
    );
    assert!(
        withheld_arms == 0,
        "pagination must preserve every questioned spine clip record"
    );
    assert!(problems.is_empty(), "{problems:#?}");
}

/// A focal that names a symbol outside the repository is refused as one the
/// walk does not serve, on the MCP route and on the command route, and never
/// reported as a focal the graph lacks.
#[tokio::test]
async fn a_walk_from_an_external_symbol_is_refused_as_one_the_walk_does_not_serve() {
    use kin_model::EntityStore as _;
    let (_dir, state) = fixture().await;
    let symbol = kin_model::ExternalSymbol::new(
        kin_model::ScipPackage::new("npm", "typescript", "5.9.3").unwrap(),
        vec![
            kin_model::ScipDescriptor::namespace("lib.es5.d.ts"),
            kin_model::ScipDescriptor::type_("Array"),
            kin_model::ScipDescriptor::method("map"),
        ],
    )
    .unwrap();
    let node = symbol.to_reference().unwrap();
    state
        .graph
        .apply_transaction_delta(&kin_model::TransactionDelta {
            external_reference_deltas: vec![kin_model::ExternalReferenceDelta::Added {
                new: node.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    let address = format!("external_reference:{}", node.id.0);

    let (daemon, _) = served(&state, &json!({ "focal": address, "direction": "calls" })).await;
    let answer = text(&daemon);
    assert_eq!(daemon.is_error, Some(true), "{answer}");
    assert!(answer.contains("external_symbol_not_served"), "{answer}");
    assert!(answer.contains("Array.map"), "{answer}");
    assert!(!answer.contains("no entity found"), "{answer}");

    let (status, body) = post(
        &state,
        "/commands/trace-data-flow",
        json!({ "focal": address }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.contains("external_symbol_not_served"), "{body}");
    assert!(!body.contains("no entity found"), "{body}");
}
