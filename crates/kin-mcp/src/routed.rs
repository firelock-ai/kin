// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One tool for a client that loads every tool it is handed.
//!
//! An eager client sends every tool definition it holds with every request. In
//! the corrected rerun pilot of 2026-09-22, Codex CLI 0.153.4 folded Kin's
//! server into one namespace tool carrying the `agent-query` profile's 15
//! nested schemas: 14,096 bytes, about 3,500 tokens resent on every request,
//! against about 1,100 tokens for the raw arm's four tools. Over 32 requests
//! that was about 60 percent of a 27 percent input-token gap, and the model
//! never called a Kin tool.
//!
//! So the routed profiles serve exactly one tool, [`TOOL_NAME`], taking a
//! `command` and its `args`. Its description is one line per core command and
//! one example. Nothing else is lost to that shortness: `describe` returns the
//! args schema of any command or registered tool and lists every tool the
//! commands do not name, and `call` runs any of them, so every tool this
//! surface may reach stays reachable from the one definition. The name of any
//! registered tool, and of the `kin` CLI subcommand for the same capability,
//! also works as the command, which is what keeps the CLI, the named tools and
//! this surface one vocabulary. It runs the other way too: `kin source`, `kin
//! describe` and `kin call` are CLI commands, so an agent with a shell that
//! types a word these instructions teach gets the same answer there.
//!
//! Two surfaces, one per [`RoutedSurface`]. `agent-routed` carries Kin's
//! writes: `session` opens the session `mutate` needs, and `mutate` is
//! `kin_mutate`, entity-addressed and atomic. `agent-routed-query` is the same
//! surface without a write path.
//!
//! A routed call is rewritten, before anything reads its name, into the named
//! tool it stands for: the dispatcher, the profile's belt defaults, the
//! response budget, the negative-evidence spec and the `_kin` envelope all see
//! that named tool, so a routed answer is the named answer. The only answers
//! made here are `describe` and a call that did not validate, and both reach
//! the caller through the same envelope. Hints inside an answer that name a
//! tool are presented as the command that reaches it here, by
//! [`rewrite_hints`]; the `_kin` envelope is never rewritten.
//!
//! The command's args are checked against the named tool's registered schema
//! before dispatch, with one rule stricter than that schema: a field the tool
//! does not declare is refused rather than ignored. A named tool ignores a
//! misspelled field in silence and answers a question nobody asked. A small
//! model that misnames a field here gets the fields and an example back, and
//! recovers in one turn. The five response-shape fields every call honors
//! through the response budget are the exception wherever the schema is open.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use crate::types::{
    ContentBlock, ToolAnnotations, ToolCallParams, ToolCallResult, ToolDefinition, ToolsListResult,
};

/// The routed tool's name, and the one name a routed profile serves.
pub const TOOL_NAME: &str = "kin";

/// The most bytes a routed profile's serialized `tools/list` may cost.
///
/// The founder-approved budget for the routed design, about 800 tokens at four
/// bytes a token, against the 14,610 bytes `agent-query` served at 97c719c8d.
/// Adding `session`, `mutate`, `path` and `call` did not need a larger one.
pub const ROUTED_LIST_CEILING_BYTES: usize = 3_200;

/// Which routed surface a connection serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedSurface {
    /// Whether this surface carries Kin's writes: `session`, `mutate`, and a
    /// `call` to a tool the registry does not annotate read-only.
    pub writes: bool,
    /// Whether `source` serves an entity's body with each line marked by its
    /// offset in the entity, as [`crate::entity_lines`] presents it. Never on
    /// a surface that writes, which restates bodies exactly.
    pub numbered: bool,
}

impl RoutedSurface {
    /// `agent-routed`, the default `kin setup` writes for an eager client.
    pub const WITH_WRITES: Self = Self {
        writes: true,
        numbered: false,
    };
    /// `agent-routed-query`, the same commands with no write path.
    pub const READ_ONLY: Self = Self {
        writes: false,
        numbered: true,
    };

    /// The `--tool-profile` token that serves this surface.
    pub fn profile(self) -> &'static str {
        if self.writes {
            "agent-routed"
        } else {
            "agent-routed-query"
        }
    }
}

/// Fields every dispatched call honors through [`crate::budget::ResponseBudget`]
/// whatever its tool declares, with the JSON type each takes.
///
/// Accepted wherever the command's schema is open. A schema that closes itself
/// with `additionalProperties: false` is taken at its word.
const RESPONSE_SHAPE_FIELDS: [(&str, &str); 5] = [
    ("max_chars", "integer"),
    ("max_response_chars", "integer"),
    ("explain", "boolean"),
    ("compact", "boolean"),
    (crate::budget::ANSWER_ONLY_PARAM, "boolean"),
];

/// The command that answers with a schema rather than a tool.
const DESCRIBE: &str = "describe";

/// The command that runs any other registered tool by name.
const CALL: &str = "call";

/// The example the served description carries, and the one a refusal with no
/// command to go on falls back to.
const HEADLINE_EXAMPLE: &str =
    r#"{"command":"locate","args":{"query":"where failed requests are retried"}}"#;

/// One named tool a command answers with.
struct Variant {
    /// The registered tool it dispatches to.
    tool: &'static str,
    /// When this variant answers, for `describe`. Empty for a command with one.
    when: &'static str,
    /// One valid `args` object, as JSON text.
    example: &'static str,
}

/// One routed command.
struct Command {
    name: &'static str,
    /// The line the served description carries for it. `source` and `call`
    /// are worded per connection by [`command_line`].
    line: &'static str,
    variants: &'static [Variant],
    /// Served only on a surface with writes.
    writes: bool,
    /// The `kin` CLI subcommand for the same capability, empty when the CLI
    /// has none. It is also accepted as the command, and a hint names the
    /// command by it, since it runs in a shell as well.
    cli: &'static str,
}

/// Every command, in the order the served description lists them.
///
/// The founder-approved set is locate, search, context, refs, trace, impact,
/// source, status and describe. `read` joined it because the cohort's Kin arms
/// read artifacts more than they used any other Kin tool. `path` split from
/// `trace` so each describes only its own tool's fields. `session` and `mutate`
/// are the entity-addressed write path, `exec` runs the project's toolchain
/// over what they wrote, and `call` reaches every other tool.
const COMMANDS: &[Command] = &[
    Command {
        name: "locate",
        line: "locate {query}: find code by what it does",
        variants: &[Variant {
            tool: "semantic_locate",
            when: "",
            example: r#"{"query":"where failed requests are retried"}"#,
        }],
        writes: false,
        cli: "kin locate",
    },
    Command {
        name: "search",
        line: "search {query}: declarations by name, kind or language; {literal}: exact text",
        variants: &[
            Variant {
                tool: "semantic_search",
                when: "args name a query: declarations by name, kind or language",
                example: r#"{"query":"parse_config"}"#,
            },
            Variant {
                tool: crate::handlers::lexical::TOOL_NAME,
                when: "args name a literal, or a cursor to page one: exact text in the graph",
                example: r#"{"literal":"retry_after"}"#,
            },
        ],
        writes: false,
        cli: "kin search",
    },
    Command {
        name: "context",
        line: "context {entity_id|entities|question}: code and routes around entities",
        variants: &[Variant {
            tool: "get_context_pack",
            when: "",
            example: r#"{"question":"how are failed requests retried"}"#,
        }],
        writes: false,
        cli: "kin context",
    },
    Command {
        name: "refs",
        line: "refs {entity_id|query}: callers, importers and references",
        variants: &[Variant {
            tool: "find_references",
            when: "",
            example: r#"{"query":"parse_config"}"#,
        }],
        writes: false,
        cli: "kin refs",
    },
    Command {
        name: "trace",
        line: "trace {focal}: the call chain out from one entity",
        variants: &[Variant {
            tool: "trace_data_flow",
            when: "",
            example: r#"{"focal":"parse_config"}"#,
        }],
        writes: false,
        cli: "kin trace-data-flow",
    },
    Command {
        name: "path",
        line: "path {from, to}: how one entity reaches another",
        variants: &[Variant {
            tool: crate::handlers::path::TOOL_NAME,
            when: "",
            example: r#"{"from":"main","to":"parse_config"}"#,
        }],
        writes: false,
        cli: "kin path",
    },
    Command {
        name: "impact",
        line: "impact {entity_ids}: what a change could affect",
        variants: &[Variant {
            tool: "impact_analysis",
            when: "",
            example: r#"{"entity_ids":["<entity id from kin locate>"]}"#,
        }],
        writes: false,
        cli: "kin impact",
    },
    Command {
        name: "source",
        line: "",
        variants: &[Variant {
            tool: "get_entity_source",
            when: "",
            example: r#"{"entity_id":"<entity id from kin locate>"}"#,
        }],
        writes: false,
        cli: "kin source",
    },
    Command {
        name: "status",
        line: "status {}: graph counts and freshness",
        variants: &[Variant {
            tool: "kin_graph_status",
            when: "",
            example: "{}",
        }],
        writes: false,
        cli: "kin graph status",
    },
    Command {
        name: "init",
        line: "init {path}: set this folder up as a Kin repository, when Kin says it is not one",
        variants: &[Variant {
            tool: crate::repository_init::TOOL_NAME,
            when: "",
            example: "{}",
        }],
        // It creates a store and the repository's canonical state, so the
        // read-only surface never carries it.
        writes: true,
        cli: "kin init",
    },
    Command {
        name: "session",
        line: "session {vendor, client_name, cwd}: open the write session mutate needs",
        variants: &[Variant {
            tool: "kin_session_start",
            when: "",
            example: r#"{"vendor":"codex","client_name":"Codex CLI","cwd":"/path/to/repo"}"#,
        }],
        writes: true,
        cli: "",
    },
    Command {
        name: "mutate",
        line: "mutate {session_id, operations}: patch anchors or update entity bodies atomically",
        variants: &[Variant {
            tool: "kin_mutate",
            when: "",
            example: r#"{"session_id":"<session_id from kin call kin_session_start>","operations":[{"verb":"patch","target":"<entity id>","payload":{"EntitySourcePatch":{"source_base":{"schema":"kin.entity.source_base.v1","context":{"repository_id":"<copy from source_base>","workspace_id":"<copy from source_base>","workspace_generation":0,"workspace_head_hash":"<copy from source_base>","workspace_tree_hash":"<copy from source_base>"},"entity_id":"<entity id>","artifact_id":"<copy from source_base>","source_blob_hash":"<copy from source_base>","start_byte":0,"end_byte":1,"body_hash":"<copy from source_base>"},"edits":[{"old_text":"<unique exact text>","new_text":"<replacement>"}]}},"description":"what this changes"}],"summary":"one sentence for the history"}"#,
        }],
        writes: true,
        cli: "",
    },
    Command {
        name: "exec",
        line: "exec {session_id, argv}: build, test or run the project in a session workspace",
        variants: &[Variant {
            tool: crate::session_exec::TOOL_NAME,
            when: "",
            example: r#"{"session_id":"<session_id from kin call kin_session_start>","argv":["go","test","./..."]}"#,
        }],
        // It runs the project's own code and hands the manifests it writes
        // back as a change, so the read-only surface never carries it. It has
        // no CLI spelling: `kin exec` in a shell is a person's session, which
        // runs any command and keeps everything it writes but build outputs.
        writes: true,
        cli: "",
    },
    Command {
        name: DESCRIBE,
        line: "describe {command}: args and an example for any command or tool; {} lists them all",
        variants: &[],
        writes: false,
        cli: "kin describe",
    },
    Command {
        name: CALL,
        line: "",
        variants: &[],
        writes: false,
        cli: "kin call",
    },
];

/// The `kin` CLI spellings accepted as a command, after the normalization
/// [`normalize`] applies, each with the command it stands for: `kin graph
/// source` arrives as `graph_source`. Every other CLI subcommand for a routed
/// capability shares the command's own name, as `kin source` does, or, as `kin
/// trace-data-flow` does, the registered tool's.
const CLI_ALIASES: &[(&str, &str)] = &[
    ("graph_source", "source"),
    ("graph_body", "source"),
    ("graph_status", "status"),
];

/// `describe`'s own example.
const DESCRIBE_EXAMPLE: &str = r#"{"command":"trace"}"#;

/// `call`'s own example.
const CALL_EXAMPLE: &str =
    r#"{"tool":"graph_neighborhood","arguments":{"entity_id":"<entity id from kin locate>"}}"#;

/// The line one command is served under on this connection.
fn command_line(command: &Command, surface: RoutedSurface) -> String {
    match command.name {
        "source" if surface.numbered => {
            "source {entity_id}: one entity's code, lines as +N offsets from its first line"
                .to_string()
        }
        "source" => "source {entity_id}: one entity's exact code".to_string(),
        CALL if surface.writes => "call {tool, arguments}: run any other Kin tool".to_string(),
        CALL => "call {tool, arguments}: run any other read-only Kin tool".to_string(),
        _ => command.line.to_string(),
    }
}

/// The commands this surface serves, in served order.
fn served_commands(surface: RoutedSurface) -> impl Iterator<Item = &'static Command> {
    COMMANDS
        .iter()
        .filter(move |command| surface.writes || !command.writes)
}

/// The routed tool's definition, exactly as `tools/list` serves it.
///
/// Whether the connection serves entity bodies as `+N` offsets is the one
/// thing the `source` line says differently.
pub fn tool_definition(surface: RoutedSurface) -> ToolDefinition {
    let mut description = String::from(
        "This repository's semantic graph in one tool. Call it with a command and that \
         command's args; any Kin tool or kin CLI command name also works as the command.\n",
    );
    for command in served_commands(surface) {
        description.push_str(&command_line(command, surface));
        description.push('\n');
    }
    description.push_str("Example: ");
    description.push_str(HEADLINE_EXAMPLE);
    let annotations = if surface.writes {
        ToolAnnotations {
            title: "Kin graph".into(),
            read_only_hint: false,
            destructive_hint: true,
            idempotent_hint: false,
            open_world_hint: false,
        }
    } else {
        ToolAnnotations {
            title: "Kin graph".into(),
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        }
    };
    ToolDefinition {
        name: TOOL_NAME.into(),
        description,
        annotations,
        input_schema: json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": served_commands(surface).map(|command| command.name).collect::<Vec<_>>()
                },
                "args": {
                    "type": "object",
                    "description": "The command's fields, as listed above."
                }
            },
            "required": ["command"],
            "additionalProperties": false
        }),
    }
}

/// The `tools/list` a routed connection serves: the one routed tool.
pub fn served_list(surface: RoutedSurface) -> ToolsListResult {
    ToolsListResult {
        tools: vec![tool_definition(surface)],
    }
}

/// The command names this surface serves, for a check that a text naming
/// routed commands names only commands a client can call.
pub fn command_names(surface: RoutedSurface) -> Vec<&'static str> {
    served_commands(surface)
        .map(|command| command.name)
        .collect()
}

/// Whether `name` is accepted as a command on this surface, alias or not.
pub fn accepts(surface: RoutedSurface, name: &str) -> bool {
    match resolve_name(name) {
        Some(Target::Command { command, .. }) => surface.writes || !command.writes,
        Some(Target::Tool(tool)) => reachable(surface, &tool),
        None => false,
    }
}

/// One row of the name table: a command, the named tools it runs, and the
/// `kin` CLI subcommand for the same capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRow {
    pub command: &'static str,
    pub tools: Vec<&'static str>,
    pub cli: &'static str,
    pub writes: bool,
}

/// The name table `docs/mcp-tools.md` prints, one row per command.
pub fn command_table() -> Vec<CommandRow> {
    COMMANDS
        .iter()
        .map(|command| CommandRow {
            command: command.name,
            tools: command
                .variants
                .iter()
                .map(|variant| variant.tool)
                .collect(),
            cli: command.cli,
            writes: command.writes,
        })
        .collect()
}

/// What routing made of one `tools/call`.
#[derive(Debug)]
pub enum Routing {
    /// Not a routed call on this connection. Handle it as the call it is.
    NotRouted,
    /// Rewritten in place into the named tool it stands for.
    Dispatch,
    /// Answered here: `describe`, or a call that did not validate.
    Answer(ToolCallResult),
}

/// Route one call. A routed call becomes its named call in place, or an answer.
pub fn route(call: &mut ToolCallParams, surface: Option<RoutedSurface>) -> Routing {
    let Some(surface) = surface else {
        return Routing::NotRouted;
    };
    if call.name != TOOL_NAME {
        return Routing::NotRouted;
    }
    match resolve(&call.arguments, surface) {
        Resolved::Dispatch { tool, args } => {
            call.name = tool;
            call.arguments = args.into_iter().collect();
            Routing::Dispatch
        }
        Resolved::Describe(value) => Routing::Answer(ToolCallResult::text(pretty(&value))),
        Resolved::Refused(value) => Routing::Answer(ToolCallResult::error(pretty(&value))),
    }
}

/// Whether a raw `tools/call` request is a routed call this server answers
/// without the graph: `describe`, or one that will be refused.
///
/// The daemon route reads this before it waits on a startup binding or admits a
/// daemon spawn, the same way it exempts the tool registry, because neither
/// answer reads a graph.
pub fn answers_locally(request: &Value, surface: Option<RoutedSurface>) -> bool {
    let Some(surface) = surface else {
        return false;
    };
    if request.pointer("/params/name").and_then(Value::as_str) != Some(TOOL_NAME) {
        return false;
    }
    let arguments: HashMap<String, Value> = request
        .pointer("/params/arguments")
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    !matches!(resolve(&arguments, surface), Resolved::Dispatch { .. })
}

enum Resolved {
    Dispatch {
        tool: String,
        args: Map<String, Value>,
    },
    Describe(Value),
    Refused(Value),
}

/// What an accepted command name stands for.
enum Target {
    /// A routed command, with the variant a tool name it was reached by forces.
    Command {
        command: &'static Command,
        variant: Option<usize>,
    },
    /// A registered tool, run by its own name.
    Tool(String),
}

/// A command name as the lookup reads it: trimmed, lower-cased, a leading
/// `kin ` dropped, and hyphens and spaces read as underscores, so the CLI's
/// `kin trace-data-flow` and `kin graph source` resolve.
fn normalize(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase();
    let trimmed = trimmed.strip_prefix("kin ").unwrap_or(&trimmed).trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut last_was_separator = false;
    for character in trimmed.chars() {
        if character == '-' || character.is_whitespace() {
            if !last_was_separator {
                out.push('_');
            }
            last_was_separator = true;
        } else {
            out.push(character);
            last_was_separator = false;
        }
    }
    out
}

fn command_named(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|command| command.name == name)
}

/// The command a registered tool is one variant of, with that variant's index.
fn command_for_tool(tool: &str) -> Option<(&'static Command, usize)> {
    COMMANDS.iter().find_map(|command| {
        command
            .variants
            .iter()
            .position(|variant| variant.tool == tool)
            .map(|index| (command, index))
    })
}

/// The registry this binary serves, built once.
fn registry() -> &'static ToolsListResult {
    static REGISTRY: OnceLock<ToolsListResult> = OnceLock::new();
    REGISTRY.get_or_init(crate::tools::tool_definitions)
}

/// The agent belt's served listing with its write half, built once. It is the
/// form every command's schema is described in.
fn belt_listing() -> &'static ToolsListResult {
    static BELT: OnceLock<ToolsListResult> = OnceLock::new();
    BELT.get_or_init(|| {
        crate::tools::served_tools_list(
            Some(&crate::tools::name_set(
                crate::tools::agent_default_tool_names(),
            )),
            true,
        )
    })
}

fn registered(tool: &str) -> Option<&'static ToolDefinition> {
    registry()
        .tools
        .iter()
        .find(|candidate| candidate.name == tool)
}

/// Whether the registry annotates `tool` read-only. Anything else, `kin_init`
/// included, is a write, and the read-only surface never runs it.
fn is_read_only(tool: &str) -> bool {
    registered(tool).is_some_and(|definition| definition.annotations.read_only_hint)
}

/// Whether this surface may run `tool`: any registered tool where it writes,
/// the read-only ones where it does not. Kin's own dispatchers are never run
/// through it, because the routed tool is the dispatcher here.
fn reachable(surface: RoutedSurface, tool: &str) -> bool {
    registered(tool).is_some() && !is_dispatcher(tool) && (surface.writes || is_read_only(tool))
}

/// The tools that only find or run other tools, which `describe` and `call`
/// stand in for on a routed connection, and `kin describe` and `kin call` in a
/// shell.
pub fn is_dispatcher(tool: &str) -> bool {
    tool == crate::tool_invocation::TOOL_NAME || tool == crate::handlers::tool_search::TOOL_NAME
}

/// The registered tool `name` stands for, read the way the routed tool reads
/// a command's name: trimmed, lower-cased, a leading `kin ` dropped, and
/// hyphens and spaces read as underscores. `None` for a command's name, a CLI
/// spelling of one, or a name nothing takes.
pub fn tool_named_by(name: &str) -> Option<String> {
    match resolve_name(name) {
        Some(Target::Tool(tool)) => Some(tool),
        _ => None,
    }
}

/// The routed command `name` stands for, read as [`tool_named_by`] reads it:
/// a command's own name or a `kin` CLI spelling of one. `None` for a tool's
/// name or a name nothing takes.
pub fn command_named_by(name: &str) -> Option<&'static str> {
    match resolve_name(name) {
        Some(Target::Command { command, .. }) => Some(command.name),
        _ => None,
    }
}

/// What an accepted name stands for: a command's own name, a registered tool's
/// name, or a `kin` CLI spelling of a command.
fn resolve_name(raw: &str) -> Option<Target> {
    let name = normalize(raw);
    if let Some(command) = command_named(&name) {
        return Some(Target::Command {
            command,
            variant: None,
        });
    }
    if registered(&name).is_some() {
        return Some(Target::Tool(name));
    }
    CLI_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
        .and_then(|(_, command)| command_named(command))
        .map(|command| Target::Command {
            command,
            variant: None,
        })
}

fn resolve(arguments: &HashMap<String, Value>, surface: RoutedSurface) -> Resolved {
    let Some(requested) = arguments.get("command").and_then(Value::as_str) else {
        return refused_without_command("kin needs a command.".to_string(), surface);
    };
    let Some(target) = resolve_name(requested) else {
        return refused_without_command(
            format!("There is no command '{}'.", requested.trim()),
            surface,
        );
    };
    let args = match collect_args(arguments) {
        Ok(args) => args,
        Err(problem) => {
            return match &target {
                Target::Command { command, .. } => {
                    refused_for_command(command, None, problem, surface)
                }
                Target::Tool(tool) => refused_for_tool(tool, problem),
            }
        }
    };
    match target {
        Target::Tool(tool) => run_tool(tool, args, surface),
        Target::Command { command, .. } if command.writes && !surface.writes => {
            refused_read_only(command.name)
        }
        Target::Command { command, .. } if command.name == DESCRIBE => describe(args, surface),
        Target::Command { command, .. } if command.name == CALL => call(args, surface),
        Target::Command { command, variant } => {
            let variant = match choose(command, variant, &args) {
                Ok(variant) => variant,
                Err(problem) => return refused_for_command(command, None, problem, surface),
            };
            let problems = validate(variant.tool, &args);
            if !problems.is_empty() {
                return refused_for_command(
                    command,
                    Some(variant.tool),
                    format!("{}: {}.", command.name, problems.join("; ")),
                    surface,
                );
            }
            Resolved::Dispatch {
                tool: variant.tool.to_string(),
                args,
            }
        }
    }
}

/// The command's fields as one object.
///
/// `args` is normally an object. A model that serializes it to a JSON string,
/// or sends the fields beside `args` instead of inside it, meant the same call,
/// so both are read as it; fields in both places are ambiguous and refused.
fn collect_args(arguments: &HashMap<String, Value>) -> Result<Map<String, Value>, String> {
    let mut beside: Vec<(&String, &Value)> = arguments
        .iter()
        .filter(|(key, _)| key.as_str() != "command" && key.as_str() != "args")
        .collect();
    beside.sort_by(|left, right| left.0.cmp(right.0));
    let args = object_from(arguments.get("args"))
        .map_err(|problem| problem.refusal("args", "args", "command's"))?;
    if beside.is_empty() {
        return Ok(args);
    }
    if args.is_empty() {
        return Ok(beside
            .into_iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect());
    }
    let names: Vec<&str> = beside.iter().map(|(key, _)| key.as_str()).collect();
    Err(format!(
        "Put every field inside args; {} came beside it.",
        names.join(", ")
    ))
}

/// A JSON object, a JSON string holding one, or nothing at all as the empty
/// object. Anything else says why it is not one.
fn object_from(value: Option<&Value>) -> Result<Map<String, Value>, NotFields> {
    match value {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(object)) => Ok(object.clone()),
        Some(Value::String(text)) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(object)) => Ok(object),
            Ok(_) => Err(NotFields::NotAnObject),
            Err(error) => Err(NotFields::Malformed(error)),
        },
        Some(_) => Err(NotFields::NotAnObject),
    }
}

/// Why a value sent as a command's or tool's fields is not an object of them.
///
/// A string that is not valid JSON is told apart from every other shape,
/// because the model that sent it meant an object and can only fix it from
/// where the parser stopped. Nothing is repaired or guessed from it.
enum NotFields {
    /// Another JSON type, or a JSON string that holds one.
    NotAnObject,
    /// A string that does not parse as JSON, with the parser's own account of
    /// what it expected and where.
    Malformed(serde_json::Error),
}

impl NotFields {
    /// The refusal for `subject`, which had to be an object of the `owner`
    /// fields and is sent as `field`.
    fn refusal(&self, subject: &str, field: &str, owner: &str) -> String {
        match self {
            NotFields::NotAnObject => {
                format!("{subject} must be a JSON object of the {owner} fields.")
            }
            NotFields::Malformed(error) => format!(
                "{subject} must be a JSON object of the {owner} fields. It came as a string that \
                 is not valid JSON ({error}), so nothing ran: send {field} as a JSON object, not \
                 as a string."
            ),
        }
    }
}

/// Which named tool answers, from the variant the caller forced or the fields
/// it sent.
fn choose(
    command: &'static Command,
    forced: Option<usize>,
    args: &Map<String, Value>,
) -> Result<&'static Variant, String> {
    if let Some(index) = forced {
        return Ok(&command.variants[index]);
    }
    if command.name == "search" {
        let exact_text = args.contains_key("literal") || args.contains_key("cursor");
        if exact_text && args.contains_key("query") {
            return Err("search takes a query or a literal, not both.".to_string());
        }
        return Ok(&command.variants[usize::from(exact_text)]);
    }
    Ok(&command.variants[0])
}

/// Run a registered tool by its own name, the way `call` does.
fn run_tool(tool: String, arguments: Map<String, Value>, surface: RoutedSurface) -> Resolved {
    if is_dispatcher(&tool) {
        return refusal(
            format!(
                "{tool} is not run through kin: describe with no command lists every tool this \
                 connection reaches, and call runs one."
            ),
            json!({"command": DESCRIBE, "args": {}}),
        );
    }
    if !surface.writes && !is_read_only(&tool) {
        return refused_read_only(&tool);
    }
    let problems = validate(&tool, &arguments);
    if !problems.is_empty() {
        return refused_for_tool(&tool, format!("{tool}: {}.", problems.join("; ")));
    }
    Resolved::Dispatch {
        tool,
        args: arguments,
    }
}

/// `call {tool, arguments}`: any registered tool this surface may reach.
fn call(args: Map<String, Value>, surface: RoutedSurface) -> Resolved {
    let call_command = command_named(CALL).expect("call is a command");
    let mut extra: Vec<&String> = args
        .keys()
        .filter(|key| *key != "tool" && *key != "arguments")
        .collect();
    extra.sort();
    if let Some(name) = extra.first() {
        return refused_for_command(
            call_command,
            None,
            format!("call takes tool and arguments; it does not take {name}."),
            surface,
        );
    }
    let Some(requested) = args.get("tool").and_then(Value::as_str) else {
        return refused_for_command(
            call_command,
            None,
            "call needs tool, the name of the tool to run.".to_string(),
            surface,
        );
    };
    let arguments = match object_from(args.get("arguments")) {
        Ok(arguments) => arguments,
        Err(problem) => {
            return refused_for_command(
                call_command,
                None,
                problem.refusal("call's arguments", "arguments", "tool's"),
                surface,
            )
        }
    };
    match resolve_name(requested) {
        Some(Target::Tool(tool)) => run_tool(tool, arguments, surface),
        Some(Target::Command { command, .. }) => refusal(
            format!(
                "call runs a tool by its registered name, and '{}' is a command: run it as \
                 {{\"command\":\"{}\"}} with the same args.",
                requested.trim(),
                command.name
            ),
            json!({"command": DESCRIBE, "args": {"command": command.name}}),
        ),
        None => refused_for_command(
            call_command,
            None,
            format!(
                "There is no Kin tool '{}'; describe with no command lists them.",
                requested.trim()
            ),
            surface,
        ),
    }
}

/// Everything wrong with `args` against `tool`'s registered schema, empty when
/// the call is good.
fn validate(tool: &str, args: &Map<String, Value>) -> Vec<String> {
    let Some(definition) = registered(tool) else {
        return vec![format!(
            "routes to {tool}, which this server does not register"
        )];
    };
    let schema = &definition.input_schema;
    let properties = schema.get("properties").and_then(Value::as_object);
    let closed = schema.get("additionalProperties") == Some(&Value::Bool(false));
    let mut problems = Vec::new();

    let mut names: Vec<&String> = args.keys().collect();
    names.sort();
    for name in names {
        let value = &args[name.as_str()];
        match properties.and_then(|properties| properties.get(name.as_str())) {
            Some(property) => problems.extend(check_value(name, property, value)),
            None => {
                let shape = RESPONSE_SHAPE_FIELDS
                    .iter()
                    .find(|(field, _)| !closed && *field == name.as_str());
                match shape {
                    Some((_, kind)) => problems.extend(check_type(name, kind, value)),
                    None => problems.push(format!("does not take {name}")),
                }
            }
        }
    }

    let present = |name: &str| args.get(name).is_some_and(|value| !value.is_null());
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !present(name) {
                problems.push(format!("missing {name}"));
            }
        }
    }
    // The "at least one of" rule a served schema cannot carry, read from the
    // one table the named call route enforces too.
    let alternatives = crate::input_contract::alternatives(tool);
    if !alternatives.is_empty()
        && !alternatives
            .iter()
            .any(|set| set.iter().all(|name| present(name)))
    {
        problems.push(format!(
            "needs {}",
            crate::input_contract::spell(alternatives)
        ));
    }
    problems
}

/// One field's value against its property schema. A null is read as absent.
fn check_value(name: &str, property: &Value, value: &Value) -> Option<String> {
    if value.is_null() {
        return None;
    }
    if let Some(branches) = property.get("anyOf").and_then(Value::as_array) {
        if branches
            .iter()
            .any(|branch| check_value(name, branch, value).is_none())
        {
            return None;
        }
        let kinds: Vec<&str> = branches
            .iter()
            .filter_map(|branch| branch.get("type").and_then(Value::as_str))
            .collect();
        return Some(format!("{name} must be {}", kinds.join(" or ")));
    }
    if let Some(kind) = property.get("type").and_then(Value::as_str) {
        if let Some(problem) = check_type(name, kind, value) {
            return Some(problem);
        }
    }
    if let Some(allowed) = property.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            return Some(format!(
                "{name} must be one of {}",
                enum_label(allowed, ", ")
            ));
        }
    }
    if let Some(number) = value.as_f64() {
        if let Some(minimum) = property.get("minimum").and_then(Value::as_f64) {
            if number < minimum {
                return Some(format!("{name} must be at least {minimum}"));
            }
        }
        if let Some(maximum) = property.get("maximum").and_then(Value::as_f64) {
            if number > maximum {
                return Some(format!("{name} must be at most {maximum}"));
            }
        }
    }
    if let (Some(text), Some(minimum)) = (
        value.as_str(),
        property.get("minLength").and_then(Value::as_u64),
    ) {
        if (text.chars().count() as u64) < minimum {
            return Some(format!("{name} must not be empty"));
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(minimum) = property.get("minItems").and_then(Value::as_u64) {
            if (items.len() as u64) < minimum {
                return Some(format!("{name} needs at least {minimum} item(s)"));
            }
        }
        if let Some(maximum) = property.get("maxItems").and_then(Value::as_u64) {
            if (items.len() as u64) > maximum {
                return Some(format!("{name} takes at most {maximum} items"));
            }
        }
        if let Some(kind) = property.pointer("/items/type").and_then(Value::as_str) {
            if items
                .iter()
                .any(|item| check_type(name, kind, item).is_some())
            {
                return Some(format!("{name} must be an array of {kind}s"));
            }
        }
    }
    None
}

fn check_type(name: &str, kind: &str, value: &Value) -> Option<String> {
    let matches = match kind {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => true,
    };
    let article = if kind.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    };
    (!matches).then(|| format!("{name} must be {article} {kind}"))
}

fn enum_label(values: &[Value], separator: &str) -> String {
    values
        .iter()
        .map(|value| match value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(separator)
}

/// The schema a routed caller is described: the agent belt's served form for a
/// tool the belt serves, with the same defaults a routed call gets, and the
/// registered form for any other tool.
///
/// One field is added back. The belt's `kin_mutate` leaves `session_id` out,
/// because `kin agent run` holds the session and fills it in for the model; a
/// routed caller opens its own session with `session`, so it is told the field
/// that carries it.
fn served_schema(tool: &str) -> Value {
    let mut schema = belt_listing()
        .tools
        .iter()
        .find(|served| served.name == tool)
        .or_else(|| registered(tool))
        .map(|served| served.input_schema.clone())
        .unwrap_or(Value::Null);
    if tool == "kin_mutate" {
        if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
            properties.entry("session_id").or_insert_with(|| {
                json!({
                    "type": "string",
                    "description": "The session_id kin call kin_session_start returned."
                })
            });
        }
        if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
            if !required.contains(&json!("session_id")) {
                required.push(json!("session_id"));
            }
        }
    }
    schema
}

/// The fields a tool takes, in the words a refusal uses.
fn fields_sentence(tool: &str) -> String {
    let schema = served_schema(tool);
    let fields: Vec<String> = schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| {
            properties
                .iter()
                .map(|(name, property)| format!("{name} ({})", type_label(property)))
                .collect()
        })
        .unwrap_or_default();
    let mut sentence = if fields.is_empty() {
        "It takes no fields.".to_string()
    } else {
        format!("Fields: {}.", fields.join(", "))
    };
    let mut needs: Vec<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let alternatives = crate::input_contract::alternatives(tool);
    if !alternatives.is_empty() {
        needs.push(crate::input_contract::spell(alternatives));
    }
    if !needs.is_empty() {
        sentence.push_str(&format!(" Needs {}.", needs.join(" and ")));
    }
    sentence
}

fn type_label(property: &Value) -> String {
    if let Some(values) = property.get("enum").and_then(Value::as_array) {
        return enum_label(values, "|");
    }
    if let Some(branches) = property.get("anyOf").and_then(Value::as_array) {
        return branches
            .iter()
            .filter_map(|branch| branch.get("type").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(" or ");
    }
    property
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("any")
        .to_string()
}

fn example_call(command: &str, args: &str) -> Value {
    json!({
        "command": command,
        "args": serde_json::from_str::<Value>(args).unwrap_or_else(|_| json!({})),
    })
}

/// The example a command's refusal carries: one call that works.
fn command_example(command: &Command, tool: Option<&str>) -> Value {
    match command.name {
        DESCRIBE => example_call(DESCRIBE, DESCRIBE_EXAMPLE),
        CALL => example_call(CALL, CALL_EXAMPLE),
        _ => {
            let variant = command
                .variants
                .iter()
                .find(|variant| Some(variant.tool) == tool)
                .unwrap_or(&command.variants[0]);
            example_call(command.name, variant.example)
        }
    }
}

fn refusal(message: String, example: Value) -> Resolved {
    Resolved::Refused(json!({ "message": message, "example": example }))
}

fn refused_without_command(problem: String, surface: RoutedSurface) -> Resolved {
    refusal(
        format!(
            "{problem} Commands: {}. The name of any Kin tool also works, and describe with no \
             command lists every tool.",
            command_names(surface).join(", ")
        ),
        serde_json::from_str::<Value>(HEADLINE_EXAMPLE).unwrap_or_else(|_| json!({})),
    )
}

fn refused_for_command(
    command: &'static Command,
    tool: Option<&str>,
    problem: String,
    surface: RoutedSurface,
) -> Resolved {
    let fields = match command.name {
        DESCRIBE => format!(
            "describe takes command, one of: {}, or any Kin tool's name.",
            command_names(surface).join(", ")
        ),
        CALL => {
            "call takes tool, a Kin tool's name, and arguments, that tool's fields.".to_string()
        }
        _ => fields_sentence(tool.unwrap_or(command.variants[0].tool)),
    };
    refusal(
        format!("{problem} {fields}"),
        command_example(command, tool),
    )
}

fn refused_for_tool(tool: &str, problem: String) -> Resolved {
    refusal(
        format!("{problem} {}", fields_sentence(tool)),
        json!({"command": DESCRIBE, "args": {"command": tool}}),
    )
}

/// The refusal a write gets on the read-only surface. It names the profile that
/// carries the write, because nothing on this one does.
fn refused_read_only(what: &str) -> Resolved {
    refusal(
        format!(
            "{what} writes, and this connection serves the read-only agent-routed-query profile. \
             The agent-routed profile carries Kin's writes."
        ),
        json!({"command": DESCRIBE, "args": {}}),
    )
}

fn describe(args: Map<String, Value>, surface: RoutedSurface) -> Resolved {
    let describe_command = command_named(DESCRIBE).expect("describe is a command");
    let mut extra: Vec<&String> = args.keys().filter(|key| *key != "command").collect();
    extra.sort();
    if let Some(name) = extra.first() {
        return refused_for_command(
            describe_command,
            None,
            format!("describe does not take {name}."),
            surface,
        );
    }
    let Some(requested) = args.get("command").and_then(Value::as_str) else {
        return Resolved::Describe(catalogue(surface));
    };
    match resolve_name(requested) {
        Some(Target::Command { command, .. }) if command.writes && !surface.writes => {
            refused_read_only(command.name)
        }
        Some(Target::Command { command, variant }) => {
            Resolved::Describe(description_of(command, variant, surface))
        }
        Some(Target::Tool(tool)) if is_dispatcher(&tool) => run_tool(tool, Map::new(), surface),
        Some(Target::Tool(tool)) if !surface.writes && !is_read_only(&tool) => {
            refused_read_only(&tool)
        }
        Some(Target::Tool(tool)) => match command_for_tool(&tool) {
            // A tool a command runs is described as that command, forced to
            // the variant the tool is, since that is the call that runs it.
            Some((command, index)) => {
                Resolved::Describe(description_of(command, Some(index), surface))
            }
            None => Resolved::Describe(json!({
                "command": CALL,
                "tool": tool,
                "summary": tool_summary(&tool),
                "args_schema": served_schema(&tool),
                "example": {"command": CALL, "args": {"tool": tool, "arguments": {}}},
                "note": format!(
                    "The tool's name also works as the command: {{\"command\":\"{tool}\",\"args\":{{...}}}}."
                ),
            })),
        },
        None => refused_for_command(
            describe_command,
            None,
            format!("There is no command or tool '{}'.", requested.trim()),
            surface,
        ),
    }
}

/// `describe` with no command: every command this surface serves and every
/// other tool it can reach through `call`.
fn catalogue(surface: RoutedSurface) -> Value {
    let commands: Vec<Value> = served_commands(surface)
        .map(|command| {
            json!({
                "command": command.name,
                "line": command_line(command, surface),
                "cli": (!command.cli.is_empty()).then_some(command.cli),
            })
        })
        .collect();
    let other_tools: Vec<Value> = registry()
        .tools
        .iter()
        .filter(|tool| command_for_tool(&tool.name).is_none() && reachable(surface, &tool.name))
        .map(|tool| {
            json!({
                "tool": tool.name,
                "summary": first_sentence(&tool.description),
                "writes": !tool.annotations.read_only_hint,
            })
        })
        .collect();
    json!({
        "commands": commands,
        "other_tools": other_tools,
        "usage": "Run a command with its args. Run any other tool with {\"command\":\"call\",\"args\":{\"tool\":\"<name>\",\"arguments\":{...}}}, or name the tool as the command. describe {\"command\":\"<name>\"} gives its args schema.",
    })
}

fn tool_summary(tool: &str) -> String {
    registered(tool)
        .map(|candidate| first_sentence(&candidate.description))
        .unwrap_or_default()
}

/// A registered description's first sentence, bounded, for a catalogue line.
fn first_sentence(description: &str) -> String {
    let sentence = description
        .split(". ")
        .next()
        .unwrap_or(description)
        .trim()
        .trim_end_matches('.');
    let mut out: String = sentence.chars().take(160).collect();
    if sentence.chars().count() > 160 {
        out.push_str("...");
    }
    out
}

/// `describe`'s own schema: the one optional field it takes.
fn describe_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "A command or any Kin tool's name. Omit it to list them all."
            }
        },
        "additionalProperties": false
    })
}

/// `call`'s own schema.
fn call_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "tool": {"type": "string", "description": "A Kin tool's registered name."},
            "arguments": {"type": "object", "description": "That tool's fields."}
        },
        "required": ["tool"],
        "additionalProperties": false
    })
}

fn description_of(
    command: &'static Command,
    forced: Option<usize>,
    surface: RoutedSurface,
) -> Value {
    let cli = (!command.cli.is_empty()).then_some(command.cli);
    let line = command_line(command, surface);
    match (command.name, command.variants) {
        (DESCRIBE, _) => json!({
            "command": command.name,
            "line": line,
            "cli": cli,
            "args_schema": describe_schema(),
            "example": example_call(command.name, DESCRIBE_EXAMPLE),
        }),
        (CALL, _) => json!({
            "command": command.name,
            "line": line,
            "cli": cli,
            "args_schema": call_schema(),
            "example": example_call(command.name, CALL_EXAMPLE),
        }),
        (_, [only]) => json!({
            "command": command.name,
            "line": line,
            "tool": only.tool,
            "cli": cli,
            "args_schema": served_schema(only.tool),
            "example": example_call(command.name, only.example),
        }),
        (_, variants) => {
            let listed: Vec<&Variant> = match forced {
                Some(index) => vec![&variants[index]],
                None => variants.iter().collect(),
            };
            json!({
                "command": command.name,
                "line": line,
                "cli": cli,
                "variants": listed
                    .into_iter()
                    .map(|variant| json!({
                        "when": variant.when,
                        "tool": variant.tool,
                        "args_schema": served_schema(variant.tool),
                        "example": example_call(command.name, variant.example),
                    }))
                    .collect::<Vec<_>>(),
            })
        }
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// The routed form of a hint that names `tool`: a spelling that runs both
/// through the routed tool and in a shell.
///
/// That is the `kin` CLI spelling of the command that runs the tool, which
/// the routed tool also takes as the command: `kin source` for
/// `get_entity_source`, and `kin graph status` for `kin_graph_status`, since
/// `kin status` in a shell is the workspace's status. Where the CLI has no
/// spelling for the command, and for a tool no command runs, it is `kin call`
/// with the tool's name, which runs the tool through the routed tool's `call`
/// and through the CLI's `kin call` alike. The dispatchers are named as the
/// commands that do their job here, `kin describe` and `kin call`.
///
/// Most forms are no longer than the name they replace. The `kin call` forms
/// and `kin trace-data-flow` are longer, and [`rewrite_hints`] keeps the named
/// form wherever a longer one would push an answer over its budget.
pub fn routed_form(tool: &str) -> String {
    let cli_of = |name: &str| command_named(name).map_or("", |command| command.cli);
    if tool == crate::handlers::tool_search::TOOL_NAME {
        return cli_of(DESCRIBE).to_string();
    }
    if tool == crate::tool_invocation::TOOL_NAME {
        return cli_of(CALL).to_string();
    }
    match command_for_tool(tool) {
        Some((command, _)) if !command.cli.is_empty() => command.cli.to_string(),
        _ => format!("{} {tool}", cli_of(CALL)),
    }
}

/// The refusal a named tool gets on a routed connection, which serves only
/// [`TOOL_NAME`]: the command that runs it here, or why nothing here does.
pub fn refuse_named_call(tool: &str, surface: RoutedSurface) -> ToolCallResult {
    let not_enabled = format!("tool '{tool}' is not enabled in this MCP profile.");
    let (message, example) = if registered(tool).is_none() {
        (
            format!(
                "{not_enabled} This connection serves one tool, {TOOL_NAME}; describe with no \
                 command lists everything it runs."
            ),
            json!({"name": TOOL_NAME, "arguments": {"command": DESCRIBE}}),
        )
    } else if !reachable(surface, tool) && !is_dispatcher(tool) {
        (
            format!(
                "{not_enabled} It writes, and this connection serves the read-only \
                 agent-routed-query profile. The agent-routed profile carries Kin's writes."
            ),
            json!({"name": TOOL_NAME, "arguments": {"command": DESCRIBE}}),
        )
    } else if is_dispatcher(tool) {
        (
            format!(
                "{not_enabled} This connection serves one tool, {TOOL_NAME}: describe with no \
                 command lists every tool it reaches, and call runs one."
            ),
            json!({"name": TOOL_NAME, "arguments": {"command": DESCRIBE}}),
        )
    } else {
        match command_for_tool(tool) {
            Some((command, _)) => (
                format!(
                    "{not_enabled} This connection serves one tool, {TOOL_NAME}: call it with \
                     command {} and the same fields as args.",
                    command.name
                ),
                json!({"name": TOOL_NAME, "arguments": {"command": command.name, "args": {}}}),
            ),
            None => (
                format!(
                    "{not_enabled} This connection serves one tool, {TOOL_NAME}: call it with \
                     command call, tool {tool}, and the same fields as arguments."
                ),
                json!({"name": TOOL_NAME, "arguments": {"command": CALL, "args": {"tool": tool, "arguments": {}}}}),
            ),
        }
    };
    ToolCallResult::error(pretty(&json!({ "message": message, "example": example })))
}

/// The payload keys whose string values are Kin's own hint prose, where a named
/// tool is presented as its routed form. A payload's data, bodies, names, file
/// text, change messages, is never under one of these, and the `_kin` envelope
/// is skipped whole.
const HINT_KEYS: [&str; 6] = [
    "remediation",
    "body_unavailable",
    "note",
    "hint",
    "next_step",
    "advice",
];

/// Present a finished answer's hints as the routed commands that reach what
/// they name.
///
/// A hint written for the named profiles says "read it with
/// get_entity_source", and a model on a routed profile holds no tool of that
/// name. Its routed form, "read it with kin source", is the call that works
/// here, and the same words run in a shell. Applied to the hint keys and, on
/// an error, to its message, which is Kin's own prose by construction. The
/// `_kin` envelope is left exactly as the named tool's answer carries it.
///
/// `max_bytes` is the ceiling the answer was bounded to. A block the rewrite
/// would lengthen past it keeps its named form, so presenting a hint never
/// breaks the size contract the caller asked for.
pub fn rewrite_hints(result: &mut ToolCallResult, max_bytes: usize) {
    let is_error = result.is_error == Some(true);
    let names: HashSet<&str> = registry()
        .tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect();
    for block in &mut result.content {
        let ContentBlock::Text { text } = block;
        let rewritten = match serde_json::from_str::<Value>(text) {
            Ok(mut payload) => {
                let mut changed = false;
                if let Some(object) = payload.as_object_mut() {
                    for (key, value) in object.iter_mut() {
                        if key == crate::envelope::ENVELOPE_KEY {
                            continue;
                        }
                        if is_error && key == "message" {
                            if let Value::String(message) = value {
                                changed |= rewrite_in_place(message, &names);
                            }
                            continue;
                        }
                        changed |= rewrite_value(key, value, &names);
                    }
                }
                if !changed {
                    continue;
                }
                // Rendered the way the envelope rendered it: pretty unless the
                // budget had asked for the compact form.
                let rendered = if text.starts_with("{\n") {
                    serde_json::to_string_pretty(&payload)
                } else {
                    serde_json::to_string(&payload)
                };
                match rendered {
                    Ok(rendered) => rendered,
                    Err(_) => continue,
                }
            }
            Err(_) if is_error => {
                let mut message = text.clone();
                if !rewrite_in_place(&mut message, &names) {
                    continue;
                }
                message
            }
            Err(_) => continue,
        };
        if rewritten.len() <= text.len() || rewritten.len() <= max_bytes {
            *text = rewritten;
        }
    }
}

fn rewrite_value(key: &str, value: &mut Value, names: &HashSet<&str>) -> bool {
    match value {
        Value::String(text) if HINT_KEYS.contains(&key) => rewrite_in_place(text, names),
        Value::Object(object) => {
            let mut changed = false;
            for (child_key, child) in object.iter_mut() {
                if child_key == crate::envelope::ENVELOPE_KEY {
                    continue;
                }
                changed |= rewrite_value(child_key, child, names);
            }
            changed
        }
        Value::Array(items) => {
            let mut changed = false;
            for item in items {
                changed |= rewrite_value(key, item, names);
            }
            changed
        }
        _ => false,
    }
}

/// Replace every whole-word registered tool name in `text` with its routed
/// form. Returns whether anything changed.
fn rewrite_in_place(text: &mut String, names: &HashSet<&str>) -> bool {
    let is_word = |character: char| character.is_ascii_alphanumeric() || character == '_';
    let mut out = String::with_capacity(text.len() + 16);
    let mut changed = false;
    let mut word = String::new();
    let mut flush = |word: &mut String, out: &mut String| {
        if names.contains(word.as_str()) {
            out.push_str(&routed_form(word));
            changed = true;
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    for character in text.chars() {
        if is_word(character) {
            word.push(character);
        } else {
            flush(&mut word, &mut out);
            out.push(character);
        }
    }
    flush(&mut word, &mut out);
    if changed {
        *text = out;
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRITES: RoutedSurface = RoutedSurface::WITH_WRITES;
    const READ_ONLY: RoutedSurface = RoutedSurface::READ_ONLY;

    fn call_with(arguments: Value) -> ToolCallParams {
        serde_json::from_value(json!({ "name": TOOL_NAME, "arguments": arguments }))
            .expect("a tools/call params object")
    }

    /// What one routed call comes back as, with the answer's JSON when there
    /// is one.
    fn outcome_on(
        surface: RoutedSurface,
        arguments: Value,
    ) -> (Routing, ToolCallParams, Option<Value>) {
        let mut params = call_with(arguments);
        let routing = route(&mut params, Some(surface));
        let payload = match &routing {
            Routing::Answer(result) => {
                let ContentBlock::Text { text } = &result.content[0];
                Some(serde_json::from_str(text).expect("a routed answer is JSON"))
            }
            _ => None,
        };
        (routing, params, payload)
    }

    fn refusal_on(surface: RoutedSurface, arguments: Value) -> Value {
        let (routing, _, payload) = outcome_on(surface, arguments.clone());
        match routing {
            Routing::Answer(result) => {
                assert_eq!(result.is_error, Some(true), "{arguments} was not refused");
            }
            other => panic!("{arguments} was not refused: {other:?}"),
        }
        payload.expect("a refusal carries JSON")
    }

    fn refusal(arguments: Value) -> Value {
        refusal_on(WRITES, arguments)
    }

    fn dispatched_on(surface: RoutedSurface, arguments: Value) -> ToolCallParams {
        let (routing, params, payload) = outcome_on(surface, arguments.clone());
        assert!(
            matches!(routing, Routing::Dispatch),
            "{arguments} did not dispatch: {payload:?}"
        );
        params
    }

    fn dispatched(arguments: Value) -> ToolCallParams {
        dispatched_on(WRITES, arguments)
    }

    fn works(example: &Value, surface: RoutedSurface) -> bool {
        let (routing, _, _) = outcome_on(surface, example.clone());
        match routing {
            Routing::Dispatch => true,
            Routing::Answer(result) => result.is_error != Some(true),
            Routing::NotRouted => false,
        }
    }

    #[test]
    fn file_catalogs_have_no_route_alias_discovery_or_description() {
        for surface in [WRITES, READ_ONLY] {
            for retired in ["kin_artifact_list", "list_file_entities"] {
                assert!(!catalogue(surface).to_string().contains(retired));
                for command in [
                    retired.to_string(),
                    format!("kin {retired}"),
                    format!(" KIN {} ", retired.to_uppercase().replace('_', "-")),
                    retired.replace('_', "   "),
                ] {
                    refusal_on(
                        surface,
                        json!({"command":command,"args":{"path":"src/lib.rs"}}),
                    );
                    refusal_on(
                        surface,
                        json!({"command":"describe","args":{"command":command}}),
                    );
                }
                refusal_on(
                    surface,
                    json!({"command":"call","args":{"tool":retired,"arguments":{"path":"src/lib.rs"}}}),
                );
            }
        }
    }

    /// The CLI's conversion diagnostic, `kin doctor --conversion-source`, is an
    /// operator boundary and no agent route reaches it. Its daemon request is
    /// built by that doctor flag alone, and this crate cannot name the request
    /// type at all; what this pins is the routed half: every spelling of it is
    /// refused as a command and through `call`, and nothing in the registry or
    /// the served catalogue names it.
    #[test]
    fn the_conversion_diagnostic_has_no_route_tool_or_description() {
        for surface in [WRITES, READ_ONLY] {
            for name in [
                "conversion_source",
                "conversion-source",
                "doctor",
                "kin doctor",
                "kin doctor --conversion-source",
            ] {
                assert!(!accepts(surface, name), "{name} is accepted");
                refusal_on(
                    surface,
                    json!({"command":name,"args":{"path":"src/lib.rs"}}),
                );
                refusal_on(
                    surface,
                    json!({"command":"call","args":{"tool":name,"arguments":{"path":"src/lib.rs"}}}),
                );
            }
            let served = catalogue(surface).to_string();
            assert!(!served.contains("conversion_source"), "{served}");
            assert!(!served.contains("conversion-source"), "{served}");
        }
        assert!(
            !registry()
                .tools
                .iter()
                .any(|tool| tool.name.contains("conversion") || tool.name.contains("doctor")),
            "no registered tool may reach the conversion diagnostic"
        );
    }

    #[test]
    fn whole_file_read_has_no_route_alias_discovery_or_description() {
        for surface in [WRITES, READ_ONLY] {
            assert!(!command_names(surface).contains(&"read"));
            assert!(!catalogue(surface).to_string().contains("kin_artifact_read"));
            for command in [
                "read",
                "kin read",
                "kin_artifact_read",
                "kin kin_artifact_read",
            ] {
                refusal_on(
                    surface,
                    json!({"command":command,"args":{"path":"README.md"}}),
                );
                refusal_on(
                    surface,
                    json!({"command":"describe","args":{"command":command}}),
                );
            }
            refusal_on(
                surface,
                json!({"command":"call","args":{"tool":"kin_artifact_read","arguments":{"path":"README.md"}}}),
            );
            refusal_on(
                surface,
                json!({"command":"locate","args":{"query":"config","granularity":"file"}}),
            );
        }
    }

    /// Setting a folder up creates a store and the repository's canonical
    /// state, so it is a write: the read-only surface neither lists it nor runs
    /// it by any name, and says which profile does.
    #[test]
    fn the_read_only_surface_never_lists_or_runs_init() {
        assert!(!command_names(READ_ONLY).contains(&"init"));
        let listed = tool_definition(READ_ONLY);
        assert!(
            !listed.description.contains("init {path}"),
            "{}",
            listed.description
        );
        assert!(
            !listed.input_schema["properties"]["command"]["enum"]
                .as_array()
                .unwrap()
                .contains(&json!("init")),
            "{}",
            listed.input_schema
        );
        for arguments in [
            json!({"command": "init"}),
            json!({"command": "init", "args": {"path": "/work/app"}}),
            json!({"command": crate::repository_init::TOOL_NAME}),
            json!({"command": "kin init"}),
            json!({"command": "call", "args": {"tool": crate::repository_init::TOOL_NAME, "arguments": {}}}),
            json!({"command": "describe", "args": {"command": "init"}}),
        ] {
            let refused = refusal_on(READ_ONLY, arguments.clone());
            let message = refused["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("read-only agent-routed-query profile")
                    && message.contains("The agent-routed profile carries Kin's writes."),
                "{arguments}: {refused}"
            );
        }
        let catalogue = catalogue(READ_ONLY).to_string();
        assert!(
            !catalogue.contains(crate::repository_init::TOOL_NAME),
            "{catalogue}"
        );

        // The write surface lists it and runs it as the named tool.
        assert!(command_names(WRITES).contains(&"init"));
        let params = dispatched(json!({"command": "init", "args": {}}));
        assert_eq!(params.name, crate::repository_init::TOOL_NAME);
    }

    /// The routed tool's annotations are a claim about everything reachable
    /// through it: read-only and idempotent only where no reachable tool
    /// writes, and never where one does.
    #[test]
    fn the_routed_tool_claims_read_only_only_where_nothing_it_reaches_writes() {
        for surface in [WRITES, READ_ONLY] {
            let reaches_a_write = crate::tools::tool_definitions()
                .tools
                .iter()
                .any(|tool| reachable(surface, &tool.name) && !tool.annotations.read_only_hint);
            let annotations = tool_definition(surface).annotations;
            assert_eq!(annotations.read_only_hint, !reaches_a_write, "{surface:?}");
            assert_eq!(annotations.idempotent_hint, !reaches_a_write, "{surface:?}");
            if reaches_a_write {
                assert!(annotations.destructive_hint, "{surface:?}");
            }
        }
        assert!(!tool_definition(WRITES).annotations.read_only_hint);
        assert!(tool_definition(READ_ONLY).annotations.read_only_hint);
    }

    /// Both served listings fit the budget the design was approved against,
    /// serve exactly the one tool, and carry one line per served command.
    #[test]
    fn each_routed_listing_serves_one_tool_under_its_ceiling() {
        let exact_read_only = RoutedSurface {
            numbered: false,
            ..READ_ONLY
        };
        for surface in [WRITES, READ_ONLY, exact_read_only] {
            let numbered = surface.numbered;
            let served = served_list(surface);
            let names: Vec<&str> = served.tools.iter().map(|tool| tool.name.as_str()).collect();
            assert_eq!(names, vec![TOOL_NAME]);
            let bytes = serde_json::to_string(&served)
                .expect("a tool listing serializes")
                .len();
            println!(
                "tools/list bytes: {} numbered={numbered} {bytes}, about {} tokens at four bytes \
                 a token, ceiling {ROUTED_LIST_CEILING_BYTES}",
                surface.profile(),
                bytes / 4
            );
            assert!(bytes <= ROUTED_LIST_CEILING_BYTES, "{bytes} bytes");
            let description = &served.tools[0].description;
            for command in COMMANDS {
                let listed = description
                    .lines()
                    .any(|line| line.starts_with(&format!("{} {{", command.name)));
                assert_eq!(
                    listed,
                    surface.writes || !command.writes,
                    "{} on {}: {description}",
                    command.name,
                    surface.profile()
                );
            }
            assert!(description.contains(HEADLINE_EXAMPLE));
            assert!(!description.contains('\u{2014}'), "{description}");
            assert_eq!(
                description.contains("+N offsets"),
                numbered,
                "the source line says what the connection serves: {description}"
            );
            let entry = serde_json::to_value(&served.tools[0]).expect("serializes");
            assert_eq!(
                entry["inputSchema"]["properties"]["command"]["enum"],
                json!(command_names(surface))
            );
            assert_eq!(
                entry["annotations"]["readOnlyHint"],
                json!(!surface.writes),
                "a surface that writes must not report itself read-only"
            );
        }
    }

    /// Every read command runs a read-only tool the query belt serves, and the
    /// two write commands run exactly the write path `kin_mutate` needs.
    #[test]
    fn commands_run_the_tools_the_design_names() {
        let query: HashSet<&str> = crate::tools::agent_query_tool_names()
            .iter()
            .copied()
            .collect();
        let default: HashSet<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .collect();
        let registry = crate::tools::tool_definitions();
        let mut reached: Vec<&str> = Vec::new();
        for command in COMMANDS {
            for variant in command.variants {
                let tool = registry
                    .tools
                    .iter()
                    .find(|tool| tool.name == variant.tool)
                    .unwrap_or_else(|| panic!("{} is not registered", variant.tool));
                if command.writes {
                    assert!(
                        !tool.annotations.read_only_hint || variant.tool == "kin_session_start"
                    );
                    assert!(default.contains(variant.tool), "{}", variant.tool);
                } else {
                    assert!(tool.annotations.read_only_hint, "{} writes", variant.tool);
                    assert!(query.contains(variant.tool), "{}", variant.tool);
                }
                reached.push(variant.tool);
            }
        }
        reached.sort_unstable();
        assert_eq!(
            reached,
            vec![
                "find_references",
                "get_context_pack",
                "get_entity_source",
                "impact_analysis",
                "kin_graph_status",
                "kin_init",
                "kin_mutate",
                "kin_session_exec",
                "kin_session_start",
                "lexical_lookup",
                "semantic_locate",
                "semantic_search",
                "trace_data_flow",
                "trace_path",
            ]
        );
    }

    /// `describe` hands back each command's schema, and every example it gives
    /// works as written on the surface that serves the command.
    #[test]
    fn describe_returns_each_schema_and_an_example_that_works() {
        for surface in [WRITES, READ_ONLY] {
            for name in command_names(surface) {
                let (routing, _, payload) = outcome_on(
                    surface,
                    json!({"command": "describe", "args": {"command": name}}),
                );
                let payload = payload.expect("describe answers with JSON");
                match routing {
                    Routing::Answer(result) => {
                        assert_ne!(result.is_error, Some(true), "{payload}")
                    }
                    other => panic!("describe {name} did not answer: {other:?}"),
                }
                assert_eq!(payload["command"], name);
                let described: Vec<(&Value, &Value, Option<&str>)> = match payload.get("variants") {
                    Some(variants) => variants
                        .as_array()
                        .expect("variants")
                        .iter()
                        .map(|v| (&v["args_schema"], &v["example"], v["tool"].as_str()))
                        .collect(),
                    None => vec![(
                        &payload["args_schema"],
                        &payload["example"],
                        payload["tool"].as_str(),
                    )],
                };
                for (schema, example, tool) in described {
                    assert_eq!(schema["type"], "object", "{name}: {payload}");
                    if let Some(tool) = tool {
                        assert_eq!(schema, &served_schema(tool), "{name}");
                    }
                    assert!(
                        works(example, surface),
                        "the {name} example fails: {example}"
                    );
                }
            }
        }
    }

    /// `describe` with no command lists every tool the commands do not name,
    /// and on the read-only surface only the read-only ones, so "anything not
    /// listed is reachable through describe" holds on both.
    #[test]
    fn describe_with_no_command_lists_everything_reachable() {
        let registry = crate::tools::tool_definitions();
        let covered: HashSet<&str> = COMMANDS
            .iter()
            .flat_map(|command| command.variants.iter().map(|variant| variant.tool))
            .collect();
        for surface in [WRITES, READ_ONLY] {
            let (_, _, payload) = outcome_on(surface, json!({"command": "describe"}));
            let payload = payload.expect("a catalogue");
            let listed: HashSet<String> = payload["other_tools"]
                .as_array()
                .expect("other_tools")
                .iter()
                .map(|row| row["tool"].as_str().unwrap().to_string())
                .collect();
            for tool in &registry.tools {
                let reachable = surface.writes || tool.annotations.read_only_hint;
                let expected = reachable
                    && !covered.contains(tool.name.as_str())
                    && tool.name != crate::tool_invocation::TOOL_NAME
                    && tool.name != crate::handlers::tool_search::TOOL_NAME;
                assert_eq!(
                    listed.contains(&tool.name),
                    expected,
                    "{} on {}",
                    tool.name,
                    surface.profile()
                );
                if expected {
                    // And each one listed actually runs through call.
                    assert!(
                        accepts(surface, &tool.name),
                        "{} is listed but not accepted",
                        tool.name
                    );
                }
            }
            let commands: Vec<&str> = payload["commands"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["command"].as_str().unwrap())
                .collect();
            assert_eq!(commands, command_names(surface));
        }
    }

    /// A bad call comes back as an error naming the fields and carrying one
    /// call that works, whatever was wrong with it.
    #[test]
    fn a_bad_call_returns_the_fields_and_an_example_that_works() {
        for (surface, arguments, names) in [
            (
                WRITES,
                json!({"command": "locate", "args": {"q": "retries"}}),
                vec!["q", "query"],
            ),
            (
                WRITES,
                json!({"command": "locate", "args": {"query": 7}}),
                vec!["query must be a string"],
            ),
            (
                WRITES,
                json!({"command": "locate", "args": {"query": "x", "granularity": "module"}}),
                vec!["granularity must be one of entity"],
            ),
            (
                WRITES,
                json!({"command": "locate", "args": {"query": "x", "limit": 0}}),
                vec!["limit must be at least 1"],
            ),
            (
                WRITES,
                json!({"command": "source", "args": {"id": "abc"}}),
                vec!["does not take id", "missing entity_id"],
            ),
            (
                WRITES,
                json!({"command": "source"}),
                vec!["missing entity_id"],
            ),
            (
                WRITES,
                json!({"command": "path", "args": {"from": "a"}}),
                vec!["missing to", "from (string)"],
            ),
            (
                WRITES,
                json!({"command": "path", "args": {"focal": "a", "target": "b"}}),
                vec!["does not take focal", "does not take target"],
            ),
            (
                WRITES,
                json!({"command": "trace", "args": {"from": "a"}}),
                vec!["does not take from", "missing focal"],
            ),
            (
                WRITES,
                json!({"command": "search", "args": {"query": "a", "literal": "b"}}),
                vec!["not both"],
            ),
            (
                WRITES,
                json!({"command": "status", "args": {"verbose": true}}),
                vec!["does not take verbose"],
            ),
            (
                WRITES,
                json!({"command": "refs", "args": {"relation_kinds": "calls"}}),
                vec!["relation_kinds must be an array"],
            ),
            (
                WRITES,
                json!({"command": "session", "args": {"vendor": "codex"}}),
                vec!["missing client_name", "missing cwd"],
            ),
            (
                WRITES,
                json!({"command": "mutate", "args": {"summary": "x"}}),
                vec!["missing operations"],
            ),
            (
                WRITES,
                json!({"command": "locate", "args": "not json"}),
                vec!["args must be a JSON object"],
            ),
            // A string that is not valid JSON: the operation object never closes
            // before its array does. The parser's own position comes back, and
            // nothing ran.
            (
                WRITES,
                json!({"command": "mutate",
                       "args": "{\"operations\":[{\"verb\":\"patch\",\"target\":\"e1\"]}"}),
                vec![
                    "args must be a JSON object",
                    "not valid JSON",
                    "line 1 column",
                    "not as a string",
                ],
            ),
            (
                WRITES,
                json!({"command": "call",
                       "args": {"tool": "graph_neighborhood", "arguments": "{\"entity_id\":\"e1\""}}),
                vec![
                    "call's arguments must be a JSON object",
                    "not valid JSON",
                    "line 1 column",
                    "send arguments as a JSON object",
                ],
            ),
            (
                WRITES,
                json!({"command": "locate", "args": {"query": "x"}, "limit": 3}),
                vec!["beside it"],
            ),
            (
                WRITES,
                json!({"command": "find", "args": {}}),
                vec!["no command 'find'", "locate", "describe"],
            ),
            (
                WRITES,
                json!({"args": {"query": "x"}}),
                vec!["needs a command", "locate"],
            ),
            (
                WRITES,
                json!({"command": "describe", "args": {"command": "grep"}}),
                vec!["no command or tool 'grep'"],
            ),
            (
                WRITES,
                json!({"command": "call", "args": {}}),
                vec!["call needs tool"],
            ),
            (
                WRITES,
                json!({"command": "call", "args": {"tool": "nope"}}),
                vec!["no Kin tool 'nope'"],
            ),
            (
                WRITES,
                json!({"command": "call", "args": {"tool": "kin"}}),
                vec!["no Kin tool 'kin'"],
            ),
            (
                WRITES,
                json!({"command": "call", "args": {"tool": "graph_neighborhood", "arguments": {"depth": 2}}}),
                vec!["missing entity_id"],
            ),
            (
                WRITES,
                json!({"command": "call", "args": {"tool": "locate"}}),
                vec!["is a command"],
            ),
            (
                WRITES,
                json!({"command": "call", "args": {"tool": "kin_tool_call", "arguments": {}}}),
                vec!["not run through kin"],
            ),
            (
                WRITES,
                json!({"command": "kin_tool_search", "args": {"need": "x"}}),
                vec!["not run through kin"],
            ),
            (
                WRITES,
                json!({"command": "graph_neighborhood", "args": {}}),
                vec!["missing entity_id", "entity_id (string)"],
            ),
            (
                READ_ONLY,
                json!({"command": "mutate", "args": {"operations": []}}),
                vec![
                    "read-only agent-routed-query",
                    "agent-routed profile carries",
                ],
            ),
            (
                READ_ONLY,
                json!({"command": "session", "args": {}}),
                vec!["read-only"],
            ),
            (
                READ_ONLY,
                json!({"command": "kin_mutate", "args": {}}),
                vec!["read-only"],
            ),
            (
                READ_ONLY,
                json!({"command": "call", "args": {"tool": "kin_transaction_commit", "arguments": {}}}),
                vec!["kin_transaction_commit writes"],
            ),
            (
                READ_ONLY,
                json!({"command": "describe", "args": {"command": "mutate"}}),
                vec!["read-only"],
            ),
        ] {
            let refusal = refusal_on(surface, arguments.clone());
            let message = refusal["message"].as_str().expect("a refusal says why");
            for name in names {
                assert!(
                    message.contains(name),
                    "the refusal for {arguments} does not name {name}: {message}"
                );
            }
            let example = &refusal["example"];
            assert!(
                works(example, surface),
                "the example for {arguments} does not work on {}: {example}",
                surface.profile()
            );
        }
    }

    /// Only a string that fails to parse is reported as invalid JSON. A value of
    /// another type, or a valid JSON string holding something other than an
    /// object, keeps the plain refusal.
    #[test]
    fn only_a_string_that_does_not_parse_is_reported_as_invalid_json() {
        for arguments in [
            json!({"command": "locate", "args": "[\"x\"]"}),
            json!({"command": "locate", "args": 7}),
            json!({"command": "locate", "args": "\"{\\\"query\\\":\\\"x\\\"}\""}),
            json!({"command": "call", "args": {"tool": "graph_neighborhood", "arguments": [1]}}),
        ] {
            let refusal = refusal(arguments.clone());
            let message = refusal["message"].as_str().expect("a refusal says why");
            assert!(
                message.contains("must be a JSON object"),
                "{arguments}: {message}"
            );
            assert!(
                !message.contains("not valid JSON"),
                "{arguments}: {message}"
            );
        }
    }

    /// The refusal names the fields the command takes, so recovery needs no
    /// second call to `describe`.
    #[test]
    fn a_refusal_lists_the_command_fields() {
        let refusal = refusal(json!({"command": "locate", "args": {}}));
        let message = refusal["message"].as_str().unwrap();
        for field in [
            "query (string)",
            "limit (integer)",
            "granularity (entity)",
            "cursor (string)",
        ] {
            assert!(message.contains(field), "{field} missing from: {message}");
        }
        assert!(message.contains("Needs query or cursor"), "{message}");
        assert_eq!(
            refusal["example"]["args"]["query"],
            "where failed requests are retried"
        );
    }

    /// Each command reaches its tool with the fields it was given, and every
    /// alias, a registered tool name or a `kin` CLI spelling, reaches the same
    /// tool.
    #[test]
    fn each_command_and_alias_dispatches_to_its_named_tool_with_its_args() {
        // The mutation row sends the guarded form, the one `kin_mutate` admits,
        // so it also shows a nested source base reaching the tool as sent. A
        // body without a base is refused as source_base_required downstream.
        let base = crate::source_base::EntitySourceBase {
            schema: crate::source_base::SourceBaseSchema::V1,
            context: crate::source_base::SourceBaseContext {
                repository_id: "routed-test".into(),
                workspace_id: uuid::Uuid::new_v4().to_string(),
                workspace_generation: 1,
                workspace_head_hash: "a".repeat(64),
                workspace_tree_hash: "b".repeat(64),
            },
            entity_id: kin_model::EntityId::new(),
            artifact_id: kin_model::ArtifactId::new(),
            source_blob_hash: "c".repeat(64),
            start_byte: 0,
            end_byte: 12,
            body_hash: "d".repeat(64),
        };
        let edit = json!({
            "verb": "update",
            "target": base.entity_id.to_string(),
            "payload": {"EntitySourceBase": base},
            "body": "x",
            "description": "d",
        });
        for (surface, arguments, tool, expected) in [
            (
                WRITES,
                json!({"command": "locate", "args": {"query": "retries"}}),
                "semantic_locate",
                json!({"query": "retries"}),
            ),
            (
                WRITES,
                json!({"command": "search", "args": {"query": "parse", "kind": "function"}}),
                "semantic_search",
                json!({"query": "parse", "kind": "function"}),
            ),
            (
                WRITES,
                json!({"command": "search", "args": {"literal": "retry_after("}}),
                "lexical_lookup",
                json!({"literal": "retry_after("}),
            ),
            (
                WRITES,
                json!({"command": "search", "args": {"cursor": "c1"}}),
                "lexical_lookup",
                json!({"cursor": "c1"}),
            ),
            (
                WRITES,
                json!({"command": "context", "args": {"entity_id": "e1"}}),
                "get_context_pack",
                json!({"entity_id": "e1"}),
            ),
            (
                WRITES,
                json!({"command": "refs", "args": {"query": "parse"}}),
                "find_references",
                json!({"query": "parse"}),
            ),
            (
                WRITES,
                json!({"command": "trace", "args": {"focal": "a", "target": "b", "depth": 2}}),
                "trace_data_flow",
                json!({"focal": "a", "target": "b", "depth": 2}),
            ),
            (
                WRITES,
                json!({"command": "path", "args": {"from": "a", "to": "b", "max_depth": 4}}),
                "trace_path",
                json!({"from": "a", "to": "b", "max_depth": 4}),
            ),
            (
                WRITES,
                json!({"command": "impact", "args": {"entity_ids": ["e1"]}}),
                "impact_analysis",
                json!({"entity_ids": ["e1"]}),
            ),
            (
                WRITES,
                json!({"command": "source", "args": {"entity_id": "e1"}}),
                "get_entity_source",
                json!({"entity_id": "e1"}),
            ),
            (
                WRITES,
                json!({"command": "status"}),
                "kin_graph_status",
                json!({}),
            ),
            (
                WRITES,
                json!({"command": "session", "args": {"vendor": "codex", "client_name": "Codex", "cwd": "/r"}}),
                "kin_session_start",
                json!({"vendor": "codex", "client_name": "Codex", "cwd": "/r"}),
            ),
            (
                WRITES,
                json!({"command": "mutate", "args": {"session_id": "s1", "operations": [edit]}}),
                "kin_mutate",
                json!({"session_id": "s1", "operations": [edit]}),
            ),
            (
                WRITES,
                json!({"command": "call", "args": {"tool": "graph_neighborhood", "arguments": {"entity_id": "e1"}}}),
                "graph_neighborhood",
                json!({"entity_id": "e1"}),
            ),
            (
                WRITES,
                json!({"command": "call", "args": {"tool": "kin_session_end", "arguments": {"session_id": "s1"}}}),
                "kin_session_end",
                json!({"session_id": "s1"}),
            ),
            (
                READ_ONLY,
                json!({"command": "call", "args": {"tool": "get_entity", "arguments": {"entity_id": "e1"}}}),
                "get_entity",
                json!({"entity_id": "e1"}),
            ),
            // Registered tool names as the command.
            (
                WRITES,
                json!({"command": "get_entity_source", "args": {"entity_id": "e1"}}),
                "get_entity_source",
                json!({"entity_id": "e1"}),
            ),
            (
                WRITES,
                json!({"command": "lexical_lookup", "args": {"literal": "x"}}),
                "lexical_lookup",
                json!({"literal": "x"}),
            ),
            (
                WRITES,
                json!({"command": "graph_neighborhood", "args": {"entity_id": "e1"}}),
                "graph_neighborhood",
                json!({"entity_id": "e1"}),
            ),
            (
                WRITES,
                json!({"command": "kin_mutate", "args": {"session_id": "s1", "operations": [{"verb": "delete", "target": "a.txt", "description": "d"}]}}),
                "kin_mutate",
                json!({"session_id": "s1", "operations": [{"verb": "delete", "target": "a.txt", "description": "d"}]}),
            ),
            (
                WRITES,
                json!({"command": "get_entity_body", "args": {"entity_id": "e1"}}),
                "get_entity_body",
                json!({"entity_id": "e1"}),
            ),
            (
                READ_ONLY,
                json!({"command": "call", "args": {"tool": "get_entity_source", "arguments": {"entity_id": "e1"}}}),
                "get_entity_source",
                json!({"entity_id": "e1"}),
            ),
            // The `kin` CLI's spellings.
            (
                WRITES,
                json!({"command": "kin trace-data-flow", "args": {"focal": "a"}}),
                "trace_data_flow",
                json!({"focal": "a"}),
            ),
            (
                WRITES,
                json!({"command": "graph source", "args": {"entity_id": "e1"}}),
                "get_entity_source",
                json!({"entity_id": "e1"}),
            ),
            (
                WRITES,
                json!({"command": "kin graph status"}),
                "kin_graph_status",
                json!({}),
            ),
            (
                READ_ONLY,
                json!({"command": "kin path", "args": {"from": "a", "to": "b"}}),
                "trace_path",
                json!({"from": "a", "to": "b"}),
            ),
            // Forgiven: case, a stringified args object, fields beside args.
            (
                WRITES,
                json!({"command": " Locate ", "args": "{\"query\":\"x\"}"}),
                "semantic_locate",
                json!({"query": "x"}),
            ),
            (
                WRITES,
                json!({"command": "locate", "query": "x", "limit": 3}),
                "semantic_locate",
                json!({"query": "x", "limit": 3}),
            ),
            (
                WRITES,
                json!({"command": "call",
                       "args": {"tool": "graph_neighborhood", "arguments": "{\"entity_id\":\"e1\"}"}}),
                "graph_neighborhood",
                json!({"entity_id": "e1"}),
            ),
            // The response-shape fields the budget honors on every open schema.
            (
                WRITES,
                json!({"command": "refs", "args": {"query": "p", "explain": true, "max_chars": 5000}}),
                "find_references",
                json!({"query": "p", "explain": true, "max_chars": 5000}),
            ),
            // A null is an absent field, passed through as the caller sent it.
            (
                WRITES,
                json!({"command": "locate", "args": {"query": "x", "cursor": null}}),
                "semantic_locate",
                json!({"query": "x", "cursor": null}),
            ),
        ] {
            let params = dispatched_on(surface, arguments.clone());
            assert_eq!(params.name, tool, "{arguments}");
            let got: Value = serde_json::to_value(&params.arguments).unwrap();
            assert_eq!(got, expected, "{arguments} reached {tool} with other args");
        }
    }

    /// Off a routed profile the name is not routed at all, so no other profile
    /// gains a way around its own tool list.
    #[test]
    fn only_a_routed_profile_routes_it() {
        let mut params = call_with(json!({"command": "status"}));
        assert!(matches!(route(&mut params, None), Routing::NotRouted));
        assert_eq!(params.name, TOOL_NAME);
        let mut named = serde_json::from_value::<ToolCallParams>(
            json!({"name": "semantic_locate", "arguments": {"query": "x"}}),
        )
        .unwrap();
        assert!(matches!(
            route(&mut named, Some(WRITES)),
            Routing::NotRouted
        ));
    }

    /// `describe` and a refusal read no graph; a dispatch does.
    #[test]
    fn only_a_dispatch_waits_on_the_graph() {
        let request = |arguments: Value| {
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": TOOL_NAME, "arguments": arguments}})
        };
        let routed = Some(WRITES);
        assert!(answers_locally(
            &request(json!({"command": "describe", "args": {"command": "locate"}})),
            routed
        ));
        assert!(answers_locally(
            &request(json!({"command": "locate", "args": {}})),
            routed
        ));
        assert!(answers_locally(&request(json!({})), routed));
        assert!(!answers_locally(
            &request(json!({"command": "locate", "args": {"query": "x"}})),
            routed
        ));
        assert!(!answers_locally(
            &request(json!({"command": "locate", "args": {"query": "x"}})),
            None
        ));
        assert!(!answers_locally(
            &json!({"params": {"name": "semantic_locate", "arguments": {}}}),
            routed
        ));
    }

    /// The fields a schema accepts beyond its own list are the response-shape
    /// ones, and only where the schema leaves itself open. `explain` is the
    /// one a registered schema tells callers to pass without declaring it.
    #[test]
    fn response_shape_fields_are_the_only_undeclared_ones_accepted() {
        let registry = crate::tools::tool_definitions();
        let references = registry
            .tools
            .iter()
            .find(|tool| tool.name == "find_references")
            .unwrap();
        let text = serde_json::to_string(&references.input_schema).unwrap();
        assert!(
            text.contains("explain: true")
                && references.input_schema["properties"]
                    .get("explain")
                    .is_none()
        );
        assert!(validate(
            "find_references",
            &Map::from_iter([
                ("query".to_string(), json!("p")),
                ("explain".to_string(), json!(true)),
            ])
        )
        .is_empty());
        assert_eq!(
            validate(
                "find_references",
                &Map::from_iter([
                    ("query".to_string(), json!("p")),
                    ("explain".to_string(), json!("yes")),
                ])
            ),
            vec!["explain must be a boolean".to_string()]
        );
        assert_eq!(
            validate(
                "kin_graph_status",
                &Map::from_iter([("max_chars".to_string(), json!(4000))])
            ),
            vec!["does not take max_chars".to_string()]
        );
    }

    /// A hint naming a tool reads as a spelling that reaches it both through
    /// the routed tool and in a shell, in the hint keys and in an error's
    /// message, while data keys and the `_kin` envelope keep every byte.
    #[test]
    fn hints_name_routed_commands_and_leave_data_and_envelope_alone() {
        let payload = json!({
            "rows": [{"name": "get_entity_source", "body": "fn get_entity_source() {}",
                      "body_unavailable": "no source body was read; read it with get_entity_source"}],
            "degradations": [{"remediation": "read one body with get_entity_source; see graph_neighborhood"}],
            "note": "Retrieval (semantic_locate) ranks over the vector index.",
            "advice": "check kin_graph_status, then trace_data_flow; get_entity_source reads the entity, and kin_tool_search finds the rest",
            "_kin": {"remediation": "use get_entity_source"},
        });
        let mut result = ToolCallResult::text(payload.to_string());
        rewrite_hints(&mut result, usize::MAX);
        let ContentBlock::Text { text } = &result.content[0];
        let rewritten: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            rewritten["rows"][0]["body_unavailable"],
            "no source body was read; read it with kin source"
        );
        assert_eq!(
            rewritten["degradations"][0]["remediation"],
            "read one body with kin source; see kin call graph_neighborhood"
        );
        assert_eq!(
            rewritten["note"],
            "Retrieval (kin locate) ranks over the vector index."
        );
        // A command whose CLI spelling is not its own name is named by that
        // spelling, one the CLI has none for by `kin call`, and a dispatcher
        // by the command that does its job here.
        assert_eq!(
            rewritten["advice"],
            "check kin graph status, then kin trace-data-flow; kin source reads \
             the entity, and kin describe finds the rest"
        );
        assert_eq!(
            rewritten["rows"][0]["name"], "get_entity_source",
            "data keeps its bytes"
        );
        assert_eq!(rewritten["rows"][0]["body"], "fn get_entity_source() {}");
        assert_eq!(
            rewritten["_kin"], payload["_kin"],
            "the envelope is never rewritten"
        );

        let mut error = ToolCallResult::error(
            json!({"message": "Missing required parameter: 'session_id'. Call kin_session_start first.", "_kin": {}}).to_string(),
        );
        rewrite_hints(&mut error, usize::MAX);
        let ContentBlock::Text { text } = &error.content[0];
        assert!(
            text.contains("Call kin call kin_session_start first"),
            "{text}"
        );

        let mut plain = ToolCallResult::error("Start a session with kin_session_start first.");
        rewrite_hints(&mut plain, usize::MAX);
        let ContentBlock::Text { text } = &plain.content[0];
        assert_eq!(
            text,
            "Start a session with kin call kin_session_start first."
        );
    }

    /// The Kin block `kin setup` writes for a routed client names source as
    /// `kin graph source`, a spelling that also runs in a shell. On both
    /// surfaces the routed tool takes it, with or without its leading `kin`,
    /// and routes it to exactly the call `source` routes to, the same tool with
    /// the same arguments.
    #[test]
    fn graph_source_routes_exactly_as_source_does() {
        let args = json!({"entity_id": "00000000-0000-0000-0000-000000000001"});
        for surface in [WRITES, READ_ONLY] {
            let source = dispatched_on(surface, json!({"command": "source", "args": args}));
            assert_eq!(source.name, "get_entity_source");
            for spelling in ["graph source", "kin graph source"] {
                assert!(accepts(surface, spelling), "{spelling}");
                let routed = dispatched_on(surface, json!({"command": spelling, "args": args}));
                assert_eq!(routed.name, source.name, "{spelling}");
                assert_eq!(routed.arguments, source.arguments, "{spelling}");
            }
        }
    }

    /// Every CLI spelling is accepted and runs what its command runs, a hint
    /// names each command's tools by that command's CLI spelling, or by `kin
    /// call` where the CLI has none, and the name table covers every command.
    /// The words the routed instructions teach, `kin source`, `kin describe`
    /// and `kin call`, are the CLI spellings of their commands.
    #[test]
    fn the_name_table_is_one_vocabulary() {
        for (alias, command) in CLI_ALIASES {
            assert!(command_named(command).is_some(), "{alias} names no command");
            assert!(accepts(WRITES, alias), "{alias} is not accepted");
        }
        let table = command_table();
        assert_eq!(
            table.iter().map(|row| row.command).collect::<Vec<_>>(),
            COMMANDS
                .iter()
                .map(|command| command.name)
                .collect::<Vec<_>>()
        );
        for (command, cli) in [
            ("source", "kin source"),
            (DESCRIBE, "kin describe"),
            (CALL, "kin call"),
        ] {
            let row = table
                .iter()
                .find(|row| row.command == command)
                .expect("a row");
            assert_eq!(row.cli, cli, "{command}");
        }
        for row in &table {
            if !row.cli.is_empty() {
                assert!(
                    accepts(WRITES, row.cli),
                    "{}'s CLI spelling {} is not accepted",
                    row.command,
                    row.cli
                );
                let command = command_named(row.command).expect("a command");
                // The command's own example, run once by its name and once by
                // its CLI spelling, comes out the same.
                let by_name = command_example(command, None);
                let mut by_cli = by_name.clone();
                by_cli["command"] = json!(row.cli);
                let (named, named_params, named_payload) = outcome_on(WRITES, by_name.clone());
                let (spelled, spelled_params, spelled_payload) = outcome_on(WRITES, by_cli.clone());
                match (&named, &spelled) {
                    (Routing::Dispatch, Routing::Dispatch) => {
                        assert!(
                            row.tools.is_empty()
                                || row.tools.contains(&spelled_params.name.as_str()),
                            "{} reached {}",
                            row.cli,
                            spelled_params.name
                        );
                        assert_eq!(spelled_params.name, named_params.name, "{by_cli}");
                        assert_eq!(spelled_params.arguments, named_params.arguments, "{by_cli}");
                    }
                    (Routing::Answer(named), Routing::Answer(spelled)) => {
                        assert_eq!(named.is_error, spelled.is_error, "{by_cli}");
                        assert_eq!(named_payload, spelled_payload, "{by_cli}");
                    }
                    other => panic!("{by_name} and {by_cli} routed apart: {other:?}"),
                }
            }
            for tool in &row.tools {
                let expected = if row.cli.is_empty() {
                    format!("kin call {tool}")
                } else {
                    row.cli.to_string()
                };
                assert_eq!(routed_form(tool), expected, "{tool}");
            }
        }
        assert_eq!(
            routed_form("graph_neighborhood"),
            "kin call graph_neighborhood"
        );
        // The dispatchers a routed connection stands `describe` and `call` in
        // for are named as those commands.
        assert_eq!(
            routed_form(crate::handlers::tool_search::TOOL_NAME),
            "kin describe"
        );
        assert_eq!(routed_form(crate::tool_invocation::TOOL_NAME), "kin call");
    }

    /// Every form a hint can name a tool by runs through the routed tool and
    /// reaches the tool it replaced, on each surface that reaches that tool:
    /// a CLI spelling the routed tool takes as the command, or `kin call` with
    /// the tool's name. The dispatchers are named as the commands that do
    /// their job here. The CLI's own test holds the same spellings against its
    /// command tree, so each also runs in a shell.
    #[test]
    fn every_hint_form_reaches_the_tool_it_replaced() {
        for tool in &crate::tools::tool_definitions().tools {
            let name = tool.name.as_str();
            let form = routed_form(name);
            let spelled = form
                .strip_prefix("kin ")
                .unwrap_or_else(|| panic!("{name}'s form {form} is not a kin spelling"));
            if is_dispatcher(name) {
                let stands_in = if name == crate::handlers::tool_search::TOOL_NAME {
                    DESCRIBE
                } else {
                    CALL
                };
                assert_eq!(spelled, stands_in, "{name}");
                continue;
            }
            for surface in [WRITES, READ_ONLY] {
                if !reachable(surface, name) {
                    continue;
                }
                let reached = match spelled.strip_prefix("call ") {
                    Some(called) => match resolve_name(called) {
                        Some(Target::Tool(called)) => reachable(surface, &called) && called == name,
                        _ => false,
                    },
                    None => match resolve_name(&form) {
                        Some(Target::Command { command, .. }) => {
                            (surface.writes || !command.writes)
                                && command.variants.iter().any(|variant| variant.tool == name)
                        }
                        Some(Target::Tool(named)) => named == name,
                        None => false,
                    },
                };
                assert!(
                    reached,
                    "{form} does not reach {name} on {}",
                    surface.profile()
                );
            }
        }
    }

    /// A hint that would grow past the answer's budget keeps its named form.
    #[test]
    fn a_hint_never_pushes_an_answer_over_its_budget() {
        let payload = json!({"note": "see graph_neighborhood"});
        let original = serde_json::to_string_pretty(&payload).unwrap();
        let mut tight = ToolCallResult::text(original.clone());
        rewrite_hints(&mut tight, original.len());
        let ContentBlock::Text { text } = &tight.content[0];
        assert_eq!(
            text, &original,
            "a rewrite that grows past the budget was kept"
        );
        let mut roomy = ToolCallResult::text(original.clone());
        rewrite_hints(&mut roomy, 10_000);
        let ContentBlock::Text { text } = &roomy.content[0];
        assert!(text.contains("kin call graph_neighborhood"), "{text}");
        // Compact stays compact.
        let compact = serde_json::to_string(&json!({"note": "use get_entity_source"})).unwrap();
        let mut result = ToolCallResult::text(compact);
        rewrite_hints(&mut result, 10_000);
        let ContentBlock::Text { text } = &result.content[0];
        assert_eq!(text, r#"{"note":"use kin source"}"#);
    }

    /// A named tool called on a routed connection is told the command that
    /// runs it there, and the write path on the read-only surface is told
    /// which profile carries it.
    #[test]
    fn a_named_call_on_a_routed_connection_names_the_command_that_works() {
        let refusal_of = |tool: &str, surface: RoutedSurface| {
            let result = refuse_named_call(tool, surface);
            assert_eq!(result.is_error, Some(true));
            let ContentBlock::Text { text } = &result.content[0];
            serde_json::from_str::<Value>(text).unwrap()
        };
        let locate = refusal_of("semantic_locate", WRITES);
        assert!(locate["message"]
            .as_str()
            .unwrap()
            .contains("not enabled in this MCP profile"));
        assert!(locate["message"]
            .as_str()
            .unwrap()
            .contains("command locate"));
        assert_eq!(locate["example"]["arguments"]["command"], "locate");
        let neighborhood = refusal_of("graph_neighborhood", READ_ONLY);
        assert!(neighborhood["message"]
            .as_str()
            .unwrap()
            .contains("command call, tool graph_neighborhood"));
        let mutate = refusal_of("kin_mutate", READ_ONLY);
        assert!(mutate["message"]
            .as_str()
            .unwrap()
            .contains("agent-routed profile carries"));
        let mutate_here = refusal_of("kin_mutate", WRITES);
        assert!(mutate_here["message"]
            .as_str()
            .unwrap()
            .contains("command mutate"));
        let unknown = refusal_of("grep", WRITES);
        assert!(unknown["message"]
            .as_str()
            .unwrap()
            .contains("describe with no command"));
    }
}
