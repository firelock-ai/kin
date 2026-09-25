// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The routed profiles teach `kin locate`, `kin source`, `kin describe` and
//! `kin call`, where `kin` is the one MCP tool they serve. An agent that also
//! has a shell types those words into it. These tests hold every `kin ...`
//! spelling a routed client can read against this binary's own command tree:
//! each one runs in a shell, or it names the routed tool itself, as "the kin
//! tool" does.

use super::*;
use kin_mcp::routed::{RoutedSurface, Routing};
use serde_json::{json, Value};

fn on_cli_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

/// Every `kin` spelling in `text`: the lowercase word `kin`, then each word
/// after it, up to the first that is not a lowercase word or is the next
/// `kin`. `Kin`, the product, is not a spelling, and neither is `kin` followed
/// by a comma, a quote or a backtick, as in "one tool, kin, called with a
/// command".
fn kin_spellings(text: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let joins_a_word =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '@');
    let in_word = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-');
    let mut found = Vec::new();
    let mut at = 0;
    while at + 4 <= chars.len() {
        let starts = at == 0 || !joins_a_word(chars[at - 1]);
        if !(starts && chars[at..at + 4] == ['k', 'i', 'n', ' ']) {
            at += 1;
            continue;
        }
        let mut words = Vec::new();
        let mut next = at + 4;
        while next < chars.len() && chars[next].is_ascii_lowercase() {
            let start = next;
            while next < chars.len() && in_word(chars[next]) {
                next += 1;
            }
            let word: String = chars[start..next].iter().collect();
            if word == "kin" {
                break;
            }
            words.push(word);
            if next < chars.len() && chars[next] == ' ' {
                next += 1;
            } else {
                break;
            }
        }
        if !words.is_empty() {
            found.push(words);
        }
        at += 3;
    }
    found
}

/// Why `kin <words>` does not run in a shell, or `None` when it does.
///
/// The words are walked down the command tree for as long as each names a
/// subcommand, so `kin graph source` is one command and "kin describe lists
/// every other Kin tool" is `kin describe`. After `kin call` a registered
/// tool's name is part of the spelling, and `kin call` must run that tool.
/// After `kin describe` a command's or a tool's name is too, and `kin
/// describe` must answer it. "The kin tool" names the routed tool itself,
/// which no shell command could be mistaken for.
fn why_it_does_not_run(cli: &clap::Command, words: &[String]) -> Option<String> {
    let spelled = format!("kin {}", words.join(" "));
    if words[0] == "tool" {
        return cli.find_subcommand("tool").map(|_| {
            format!("{spelled}: `kin tool` is a CLI command, so \"the kin tool\" reads as one")
        });
    }
    let mut command = cli;
    let mut path: Vec<&str> = Vec::new();
    for word in words {
        let Some(sub) = command.get_subcommands().find(|sub| {
            sub.get_name() == word.as_str() || sub.get_all_aliases().any(|alias| alias == word)
        }) else {
            break;
        };
        path.push(sub.get_name());
        command = sub;
    }
    if path.is_empty() {
        return Some(format!(
            "{spelled}: `kin {}` is not a CLI command",
            words[0]
        ));
    }
    let registered = kin_mcp::tool_definitions();
    let is_tool = |name: &str| registered.tools.iter().any(|tool| tool.name == name);
    match (path.as_slice(), words.get(path.len())) {
        (["call"], Some(tool)) if is_tool(tool) => {
            kin_cli::commands::routed_words::refusal_for(tool)
                .map(|refusal| format!("{spelled}: `kin call` does not run {tool}: {refusal}"))
        }
        (["describe"], Some(named))
            if is_tool(named)
                || kin_mcp::routed::command_names(RoutedSurface::WITH_WRITES)
                    .contains(&named.as_str()) =>
        {
            let answer = kin_cli::commands::routed_words::describe(Some(named));
            answer
                .is_error
                .then(|| format!("{spelled}: `kin describe` refuses {named}: {}", answer.text))
        }
        _ => None,
    }
}

/// The text the routed tool answers `arguments` with, empty for a dispatch.
fn routed_answer(surface: RoutedSurface, arguments: Value) -> String {
    let mut params: kin_mcp::ToolCallParams = serde_json::from_value(json!({
        "name": kin_mcp::routed::TOOL_NAME,
        "arguments": arguments,
    }))
    .expect("a tools/call params object");
    match kin_mcp::routed::route(&mut params, Some(surface)) {
        Routing::Answer(result) => {
            let kin_mcp::ContentBlock::Text { text } = &result.content[0];
            text.clone()
        }
        Routing::Dispatch | Routing::NotRouted => String::new(),
    }
}

/// The instructions a routed connection is served at `initialize`.
fn served_instructions(surface: RoutedSurface) -> String {
    let config = kin_mcp::McpServerConfig {
        allowed_tools: Some(kin_mcp::tool_name_set(kin_mcp::agent_routed_tool_names())),
        agent_belt: true,
        routed: Some(surface),
        number_entity_lines: surface.numbered,
        ..kin_mcp::McpServerConfig::default()
    };
    let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let response = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(kin_mcp::process_daemon_message(initialize, &config))
        .expect("initialize is answered");
    response.result.expect("a result")["instructions"]
        .as_str()
        .expect("instructions")
        .to_string()
}

/// Every text a routed client can read that spells a `kin` command, labelled
/// by where it comes from.
fn routed_texts() -> Vec<(String, String)> {
    let mut texts = Vec::new();
    for surface in [RoutedSurface::WITH_WRITES, RoutedSurface::READ_ONLY] {
        let profile = surface.profile();
        texts.push((
            format!("{profile} instructions"),
            served_instructions(surface),
        ));
        let listed = kin_mcp::routed::tool_definition(surface);
        texts.push((
            format!("{profile} tools/list"),
            serde_json::to_string(&listed).unwrap(),
        ));
        texts.push((
            format!("{profile} describe"),
            routed_answer(surface, json!({"command": "describe"})),
        ));
        let mut names: Vec<String> = kin_mcp::routed::command_names(surface)
            .into_iter()
            .map(str::to_string)
            .collect();
        names.extend(
            kin_mcp::tool_definitions()
                .tools
                .into_iter()
                .map(|tool| tool.name),
        );
        for name in &names {
            texts.push((
                format!("{profile} describe {name}"),
                routed_answer(
                    surface,
                    json!({"command": "describe", "args": {"command": name}}),
                ),
            ));
            let refused = kin_mcp::routed::refuse_named_call(name, surface);
            let kin_mcp::ContentBlock::Text { text } = &refused.content[0];
            texts.push((format!("{profile} refusal of {name}"), text.clone()));
        }
    }
    for tool in kin_mcp::tool_definitions().tools {
        texts.push((
            format!("the hint naming {}", tool.name),
            kin_mcp::routed::routed_form(&tool.name),
        ));
    }
    let mut refused_names: Vec<String> = kin_mcp::routed::command_names(RoutedSurface::WITH_WRITES)
        .into_iter()
        .map(str::to_string)
        .collect();
    refused_names.extend(
        ["kin_init", "kin_tool_search", "kin_tool_call", "nope"]
            .into_iter()
            .map(str::to_string),
    );
    for name in refused_names {
        if let Some(refusal) = kin_cli::commands::routed_words::refusal_for(&name) {
            texts.push((format!("`kin call {name}`'s refusal"), refusal));
        }
    }
    for profile in [
        "agent-default",
        "agent-query",
        "agent-search",
        "agent-routed",
        "agent-routed-query",
    ] {
        texts.push((
            format!("the {profile} discovery block"),
            kin_cli::commands::setup::discovery_block(profile),
        ));
    }
    texts.push((
        "docs/mcp-tools.md".to_string(),
        include_str!("../../../docs/mcp-tools.md").to_string(),
    ));
    texts
}

/// Every `kin ...` spelling a routed client reads, in the instructions, the
/// routed tool's listing and every `describe` answer and refusal it gives,
/// the hints it rewrites, the refusals `kin call` gives, the discovery
/// blocks `kin setup` writes and docs/mcp-tools.md, runs in a shell or names
/// the routed tool itself.
#[test]
fn every_routed_spelling_runs_in_a_shell_or_names_the_kin_tool() {
    on_cli_stack(|| {
        let mut cli = Cli::command();
        cli.build();
        let texts = routed_texts();
        let mut failures = Vec::new();
        let mut checked = 0;
        for (label, text) in &texts {
            for words in kin_spellings(text) {
                checked += 1;
                if let Some(why) = why_it_does_not_run(&cli, &words) {
                    failures.push(format!("{label}: {why}"));
                }
            }
        }
        failures.dedup();
        assert!(
            failures.is_empty(),
            "{} of {checked} spellings do not run in a shell:\n{}",
            failures.len(),
            failures.join("\n")
        );
        // The reader finds the words the ticket is about, so a text that
        // lost them would not pass here by saying nothing.
        let all: Vec<String> = texts
            .iter()
            .flat_map(|(_, text)| kin_spellings(text))
            .map(|words| words.join(" "))
            .collect();
        for expected in [
            "source by entity id",
            "describe lists every other",
            "call runs any of them",
            "call graph_neighborhood",
            "tool up front and you",
        ] {
            assert!(
                all.iter().any(|spelled| spelled.starts_with(expected)),
                "no spelling reads `kin {expected}`"
            );
        }
    });
}

/// The reader takes each spelling whole and nothing that is not one.
#[test]
fn the_spelling_reader_reads_what_a_person_would() {
    assert_eq!(
        kin_spellings("Use kin refs and kin context before source."),
        vec![
            vec!["refs".to_string(), "and".to_string()],
            vec![
                "context".to_string(),
                "before".to_string(),
                "source".to_string()
            ],
        ]
    );
    assert_eq!(
        kin_spellings("`kin graph source --json`, one tool, kin, and \"kin\" and Kin tools"),
        vec![vec!["graph".to_string(), "source".to_string()]]
    );
    assert!(kin_spellings("kin_tool_call and ~/.kin/bin and `kin-managed:discovery`").is_empty());
    on_cli_stack(|| {
        let mut cli = Cli::command();
        cli.build();
        let words =
            |spelled: &str| -> Vec<String> { spelled.split(' ').map(str::to_string).collect() };
        assert!(why_it_does_not_run(&cli, &words("graph source by id")).is_none());
        assert!(why_it_does_not_run(&cli, &words("tool up front")).is_none());
        assert!(why_it_does_not_run(&cli, &words("graph")).is_none());
        assert!(why_it_does_not_run(&cli, &words("session first")).is_some());
        assert!(why_it_does_not_run(&cli, &words("frobnicate")).is_some());
    });
}

/// `kin source` is `kin graph source` at the top level: the same arguments,
/// flags and help, parsed to the same values.
#[test]
fn kin_source_takes_what_kin_graph_source_takes() {
    on_cli_stack(|| {
        let cli = Cli::command();
        let shape = |command: &clap::Command| -> Vec<(String, Option<String>, bool, String)> {
            command
                .get_arguments()
                .map(|arg| {
                    (
                        arg.get_id().to_string(),
                        arg.get_long().map(str::to_string),
                        arg.is_required_set(),
                        arg.get_help().map(ToString::to_string).unwrap_or_default(),
                    )
                })
                .collect()
        };
        let top = cli
            .find_subcommand("source")
            .expect("`kin source` is a command");
        let graph_source = cli
            .find_subcommand("graph")
            .and_then(|graph| graph.find_subcommand("source"))
            .expect("`kin graph source` is a command");
        assert_eq!(shape(top), shape(graph_source));
        assert!(!shape(top).is_empty());
        assert_eq!(top.get_about(), graph_source.get_about());

        let argv = [
            "Name",
            "--file",
            "src/lib.rs",
            "--kind",
            "function",
            "--json",
        ];
        let top_matches = Cli::command()
            .try_get_matches_from(["kin", "source"].into_iter().chain(argv))
            .expect("`kin source` parses");
        let graph_matches = Cli::command()
            .try_get_matches_from(["kin", "graph", "source"].into_iter().chain(argv))
            .expect("`kin graph source` parses");
        let (_, top_args) = top_matches.subcommand().expect("a subcommand");
        let (_, graph) = graph_matches.subcommand().expect("a subcommand");
        let (_, graph_args) = graph.subcommand().expect("a graph subcommand");
        for id in ["entity", "file", "kind"] {
            assert_eq!(
                top_args.get_one::<String>(id),
                graph_args.get_one::<String>(id),
                "{id}"
            );
        }
        assert_eq!(top_args.get_flag("json"), graph_args.get_flag("json"));
    });
}

/// `kin describe` takes an optional command, and `kin call` a tool and
/// optionally its arguments as one JSON object, `-` meaning stdin.
#[test]
fn kin_describe_and_kin_call_parse_as_the_routed_words() {
    on_cli_stack(|| {
        let subcommand = |argv: &[&str]| {
            let matches = Cli::command()
                .try_get_matches_from(argv)
                .unwrap_or_else(|error| panic!("{argv:?}: {error}"));
            let (name, args) = matches.subcommand().expect("a subcommand");
            (name.to_string(), args.clone())
        };
        let (name, args) = subcommand(&["kin", "describe"]);
        assert_eq!(name, "describe");
        assert_eq!(args.get_one::<String>("command"), None);
        let (_, args) = subcommand(&["kin", "describe", "graph source"]);
        assert_eq!(
            args.get_one::<String>("command").map(String::as_str),
            Some("graph source")
        );
        let (name, args) =
            subcommand(&["kin", "call", "graph_neighborhood", r#"{"entity_id":"e1"}"#]);
        assert_eq!(name, "call");
        assert_eq!(
            args.get_one::<String>("tool").map(String::as_str),
            Some("graph_neighborhood")
        );
        assert_eq!(
            args.get_one::<String>("arguments").map(String::as_str),
            Some(r#"{"entity_id":"e1"}"#)
        );
        let (_, args) = subcommand(&["kin", "call", "kin_mutate", "-"]);
        assert_eq!(
            args.get_one::<String>("arguments").map(String::as_str),
            Some("-")
        );
        let (_, args) = subcommand(&["kin", "call", "kin_graph_status"]);
        assert_eq!(args.get_one::<String>("arguments"), None);
        let missing = Cli::command()
            .try_get_matches_from(["kin", "call"])
            .expect_err("`kin call` needs a tool");
        assert_eq!(
            missing.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    });
}
