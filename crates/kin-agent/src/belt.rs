// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The toolbelt and the router that enforces it.
//!
//! The policy is enforced by absence and by refusal. There is no shell tool, no file-read
//! tool and no file-search tool anywhere in the belt, so there is nothing to fall back to,
//! and the router refuses by name any tool the model invents. Both halves matter: a model
//! that hallucinates a `bash` tool must be told no rather than quietly handed an empty
//! result it will read as "the command produced nothing".

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// The two local tools. Everything else the agent can do, it does through Kin.
pub const EDIT_FILE: &str = "edit_file";
pub const WRITE_FILE: &str = "write_file";

/// Prefix that marks a Kin tool in the model's belt and in the transcript. `usage.py`
/// classifies `mcp__<server>__<tool>` as an MCP call, so this is what makes a Kin call
/// countable by the analyzers the fleet already runs.
pub const KIN_TOOL_PREFIX: &str = "mcp__kin__";

/// Where a routed call goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// A Kin tool, named without the transcript prefix, on the server that serves it.
    Kin { server: usize, tool: String },
    /// One of the two local tools.
    Local(LocalTool),
    /// Not in the belt. Carries the refusal the model is told.
    Refused(String),
}

/// Where a call goes, and what goes out with it.
///
/// The arguments travel with the route because a folded belt tool rewrites them,
/// and a dispatcher that read the route from one call and the arguments from
/// another could send a two-ended question to the one-ended handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedCall {
    pub route: Route,
    /// What to send. Identical to what the model wrote unless the belt folded
    /// the tool it named.
    pub arguments: Value,
}

/// One Kin tool on the belt, bound to the server that declared it.
///
/// A run can attach several graph servers, one per repository, and every one of them
/// declares the same tool names. The binding has to travel with the tool or a call cannot
/// be sent anywhere: the model's name is the only thing the router has to go on.
#[derive(Debug, Clone)]
pub struct KinTool {
    /// Index into the run's server list.
    pub server: usize,
    /// The name the server itself declares.
    pub bare: String,
    /// The name the model calls, carrying the transcript prefix.
    pub exposed: String,
    pub description: String,
    pub schema: Value,
    /// Set when this belt tool stands for more than one server tool, so the
    /// arguments decide which one a call reaches.
    ///
    /// Marked rather than inferred from the name. `bare` holds the tool a call
    /// takes by default, which is a real server tool either way, so nothing
    /// downstream could tell a folded tool from an ordinary one by looking at
    /// it, and a router that guessed from a name would be one rename away from
    /// sending a fold's arguments to the wrong handler.
    pub folded: bool,
}

/// The prefix one server's tools carry on the model's belt.
///
/// A single-server run keeps the historical `mcp__kin__`, so a one-repository transcript
/// stays byte-identical to what the fleet's analyzers already read. Several servers each
/// get `mcp__kin_<label>__`, which holds the `mcp__<server>__<tool>` shape those analyzers
/// classify while naming the repository in every call the model makes.
pub fn tool_prefix(label: Option<&str>) -> String {
    match label {
        None => KIN_TOOL_PREFIX.to_string(),
        Some(label) => format!("mcp__kin_{label}__"),
    }
}

/// A short, stable, unique label for one repository, for use in a tool prefix.
///
/// The directory name is what an operator recognizes, so it is the source. Anything a tool
/// name cannot carry becomes `_`, and a collision takes a numeric suffix rather than
/// silently sharing a namespace with another repository.
pub fn server_label(repo: &Path, taken: &BTreeSet<String>) -> String {
    let base: String = repo
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    let base = base.trim_matches('_').to_string();
    let base = if base.is_empty() {
        "repo".to_string()
    } else {
        base
    };
    if !taken.contains(&base) {
        return base;
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}_{suffix}");
        if !taken.contains(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTool {
    Edit,
    Write,
}

/// How much of the server's surface this run puts on the model's belt.
///
/// The server's `agent-default` profile is curated for a client with room. A
/// local model's window is the binding constraint, and measured on
/// `qwen/qwen3.8-27b` the fifteen Kin tools plus the two local ones cost 6,367
/// prompt tokens before the model had read one line of code. Four of those tools
/// answer questions an agent asking, editing and publishing does not ask, so the
/// default belt withholds them and an operator who wants them says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BeltProfile {
    /// The tools an agent needs to answer, edit and publish, and nothing else.
    #[default]
    Default,
    /// Everything the server serves, minus what the harness owns.
    Wide,
}

impl BeltProfile {
    /// Read the profile a `KIN_AGENT_BELT` value asks for.
    ///
    /// Unset, empty and every value outside the two names read as the default
    /// belt. A typo is reported by the env registry's own startup validation,
    /// which is where a value neither name matches belongs, rather than guessed
    /// at here.
    pub fn from_value(value: Option<&str>) -> Self {
        match value
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("wide") => BeltProfile::Wide,
            _ => BeltProfile::Default,
        }
    }

    /// The profile this process asked for, through `KIN_AGENT_BELT`.
    pub fn from_env() -> Self {
        Self::from_value(std::env::var("KIN_AGENT_BELT").ok().as_deref())
    }

    /// The token an operator reads back in the run record.
    pub fn as_str(self) -> &'static str {
        match self {
            BeltProfile::Default => "default",
            BeltProfile::Wide => "wide",
        }
    }
}

/// Whether the default belt withholds this tool, leaving it to `KIN_AGENT_BELT=wide`.
///
/// Withholding is not removal. Every name here is still served by the MCP
/// profile, still reachable from any other client, and still on this belt when
/// the operator asks for the wide one. What it buys is window: these four cost
/// 3,239 of the belt's 21,998 schema bytes, and none of them answers a question
/// that stands between an agent and an answer, an edit or a commit.
///
/// Why each one:
///
/// - `kin_artifact_list` and `kin_artifact_read` read tracked files rather than
///   entities. They are the escape hatch for a file the parsers made no entities
///   for, which is a real capability and a rare one; on the two-hop trace run
///   that spent its whole window, the one `kin_artifact_list` call returned
///   18,435 bytes and the answer was in none of them.
/// - `graph_neighborhood` is `find_references` in one direction and
///   `trace` in the other, and the belt carries both.
/// - `kin_provenance_query` answers who changed an entity and whether it was
///   approved. That is a question about history, and an agent reaches it after
///   it has an answer, not on the way to one.
///
/// `impact_analysis` is deliberately NOT here. "What breaks if I change this" is
/// the question Kin is described as answering, and a belt that cannot ask it is
/// not the product.
pub fn is_opt_in(name: &str) -> bool {
    matches!(
        name,
        "kin_artifact_list" | "kin_artifact_read" | "graph_neighborhood" | "kin_provenance_query"
    )
}

/// The name the folded traversal tool carries on the belt.
pub const TRACE_TOOL: &str = "trace";

/// The server tool a `trace` call with no `to` goes to.
pub const TRACE_ONE_ENDPOINT: &str = "trace_data_flow";

/// The server tool a `trace` call naming both ends goes to.
pub const TRACE_TWO_ENDPOINT: &str = "trace_path";

/// Fold the two traversal tools on each server into one belt tool.
///
/// `trace_data_flow` walks out from one entity and `trace_path` finds the route
/// between two. They are the same question with a different number of ends, and
/// the server's own descriptions say so: one closes "Naming TWO things? Use
/// trace_path" and the other "One endpoint only? Use trace_data_flow". A model
/// that has to choose between them before it knows which shape its question has
/// pays for both schemas and then picks wrong, and the two cost 3,066 of the
/// belt's schema bytes between them.
///
/// The folded tool takes `from` and an optional `to`. Giving `to` asks for the
/// route between two ends; leaving it out walks the chain out from `from`.
///
/// The schema is assembled from the property definitions the server declared,
/// not written out here, so a bound, a default or a clause the server changes
/// arrives on the belt with it. `direction` is the one exception and the reason
/// it is: the two tools spell the same three directions differently, `calls`,
/// `callers` and `both` against `forward`, `reverse` and `either`, so the belt
/// names one set and [`resolve_trace_call`] translates.
///
/// A server that declares only one of the two is left exactly as it is. The fold
/// is a saving, not a contract, and half of it is a belt missing a capability.
pub fn fold_traversal(tools: &mut Vec<KinTool>) {
    let servers: BTreeSet<usize> = tools.iter().map(|tool| tool.server).collect();
    for server in servers {
        let one = tools
            .iter()
            .position(|tool| tool.server == server && tool.bare == TRACE_ONE_ENDPOINT);
        let two = tools
            .iter()
            .position(|tool| tool.server == server && tool.bare == TRACE_TWO_ENDPOINT);
        let (Some(one), Some(two)) = (one, two) else {
            continue;
        };
        let folded = folded_trace_tool(&tools[one], &tools[two]);
        let (first, second) = (one.min(two), one.max(two));
        tools[first] = folded;
        tools.remove(second);
    }
}

/// Build the folded tool from the two the server declared.
fn folded_trace_tool(one_endpoint: &KinTool, two_endpoint: &KinTool) -> KinTool {
    let property = |tool: &KinTool, name: &str| -> Option<Value> {
        tool.schema
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(name))
            .cloned()
    };
    let mut properties = Map::new();
    properties.insert(
        "from".to_string(),
        property(two_endpoint, "from").unwrap_or_else(|| json!({ "type": "string" })),
    );
    properties.insert(
        "to".to_string(),
        property(two_endpoint, "to").unwrap_or_else(|| json!({ "type": "string" })),
    );
    properties.insert(
        "direction".to_string(),
        json!({
            "type": "string",
            "enum": ["forward", "reverse", "both"],
            "default": "forward",
            "description": "`forward` walks out of `from`, `reverse` walks what reaches it, `both` merges."
        }),
    );
    for name in ["depth", "include_body", "limit_per_step", "max_chars"] {
        if let Some(declared) = property(one_endpoint, name) {
            properties.insert(name.to_string(), declared);
        }
    }
    let exposed = one_endpoint
        .exposed
        .strip_suffix(TRACE_ONE_ENDPOINT)
        .map(|prefix| format!("{prefix}{TRACE_TOOL}"))
        .unwrap_or_else(|| format!("{KIN_TOOL_PREFIX}{TRACE_TOOL}"));
    KinTool {
        folded: true,
        server: one_endpoint.server,
        bare: TRACE_ONE_ENDPOINT.to_string(),
        exposed,
        description: "Walk the call and import graph from one entity. Name `to` as well and it \
                      returns the ordered hops from one to the other; leave it out and it walks \
                      the whole chain out from `from`."
            .to_string(),
        schema: json!({
            "type": "object",
            "properties": Value::Object(properties),
            "required": ["from"],
        }),
    }
}

/// Resolve a call on the folded tool to the server tool and arguments it takes.
///
/// Naming a non-empty `to` is the whole selector, because it is the one thing a
/// two-ended question has that a one-ended question does not. An empty string is
/// read as absent: a model asked for an optional argument it does not want often
/// sends `""` rather than omitting the key, and routing that to the two-ended
/// tool would refuse a question the one-ended tool answers.
pub fn resolve_trace_call(arguments: &Value) -> (&'static str, Value) {
    let named = |key: &str| arguments.get(key).cloned().filter(|value| !value.is_null());
    let to = arguments
        .get("to")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|to| !to.is_empty());
    let direction = arguments.get("direction").and_then(Value::as_str);
    let mut out = Map::new();
    if let Some(from) = named("from") {
        out.insert(
            if to.is_some() { "from" } else { "focal" }.to_string(),
            from,
        );
    }
    match to {
        Some(to) => {
            out.insert("to".to_string(), Value::String(to.to_string()));
            if let Some(direction) = direction {
                out.insert(
                    "direction".to_string(),
                    Value::String(
                        match direction {
                            "reverse" => "reverse",
                            "both" => "either",
                            _ => "forward",
                        }
                        .to_string(),
                    ),
                );
            }
            if let Some(depth) = named("depth") {
                out.insert("max_depth".to_string(), depth);
            }
            if let Some(max_chars) = named("max_chars") {
                out.insert("max_chars".to_string(), max_chars);
            }
            (TRACE_TWO_ENDPOINT, Value::Object(out))
        }
        None => {
            if let Some(direction) = direction {
                out.insert(
                    "direction".to_string(),
                    Value::String(
                        match direction {
                            "reverse" => "callers",
                            "both" => "both",
                            _ => "calls",
                        }
                        .to_string(),
                    ),
                );
            }
            for name in ["depth", "include_body", "limit_per_step", "max_chars"] {
                if let Some(value) = named(name) {
                    out.insert(name.to_string(), value);
                }
            }
            (TRACE_ONE_ENDPOINT, Value::Object(out))
        }
    }
}

/// The belt: every name the model may call this run.
#[derive(Debug, Clone)]
pub struct Belt {
    kin_tools: Vec<KinTool>,
    names: BTreeSet<String>,
    file_tools: bool,
}

/// The values `KIN_AGENT_PURE_KIN` reads as on.
///
/// Exactly the set kin-core's env registry accepts as true for a `Kind::Bool`
/// (`BOOL_TRUE` in `kin-core/src/env_registry.rs`, where this variable is
/// registered), trimmed and case-folded the same way, so the switch means one
/// thing across the product. Mirrored rather than imported because kin-agent
/// takes no kin-core dependency, and a second, looser reading is what this
/// replaced: it treated everything except `0` and `false` as on, so
/// `KIN_AGENT_PURE_KIN=off` locked the belt, which is the opposite of what the
/// word says and what the registry's validator would tell the operator.
const PURE_KIN_TRUE: [&str; 4] = ["1", "true", "yes", "on"];

/// Whether a `KIN_AGENT_PURE_KIN` value asks for the pure Kin belt.
///
/// Unset and every value outside the registry's true set read as off, which
/// leaves the full belt. A value that is neither true nor false by the
/// registry's reading is still reported by its startup validation, so a typo
/// is surfaced there rather than guessed at here.
pub fn pure_kin_requested(value: Option<&str>) -> bool {
    value.is_some_and(|value| PURE_KIN_TRUE.contains(&value.trim().to_ascii_lowercase().as_str()))
}

impl Belt {
    /// Build the belt from what the MCP servers declared. If pure Kin mode is
    /// active (via KIN_AGENT_PURE_KIN env var), local file tools are omitted.
    pub fn new(kin_tools: Vec<KinTool>) -> Self {
        let file_tools = !Self::pure_kin_default();
        Self::with_local_tools(kin_tools, file_tools)
    }

    /// Construct a pure Kin belt with no file tools on it.
    pub fn pure_kin(kin_tools: Vec<KinTool>) -> Self {
        Self::with_local_tools(kin_tools, false)
    }

    /// Construct a belt explicitly including local file tools.
    pub fn with_file_tools(kin_tools: Vec<KinTool>) -> Self {
        Self::with_local_tools(kin_tools, true)
    }

    /// Whether this process asked for a pure Kin belt, through `KIN_AGENT_PURE_KIN`.
    pub fn pure_kin_default() -> bool {
        pure_kin_requested(std::env::var("KIN_AGENT_PURE_KIN").ok().as_deref())
    }

    /// Build the belt with or without local file tools.
    pub fn with_local_tools(kin_tools: Vec<KinTool>, file_tools: bool) -> Self {
        let mut names: BTreeSet<String> =
            kin_tools.iter().map(|tool| tool.exposed.clone()).collect();
        if file_tools {
            names.insert(EDIT_FILE.to_string());
            names.insert(WRITE_FILE.to_string());
        }
        Belt {
            kin_tools,
            names,
            file_tools,
        }
    }

    /// Whether this belt includes local file tools.
    pub fn has_file_tools(&self) -> bool {
        self.file_tools
    }

    /// The prefix this belt's Kin tools carry, for a message that names one.
    ///
    /// Read off the belt rather than assumed, because a run with several repositories
    /// attached labels each server's tools, and a message naming `mcp__kin__kin_mutate`
    /// to a model whose belt carries `mcp__kin_cli__kin_mutate` names nothing it can call.
    fn kin_prefix(&self) -> &str {
        self.kin_tools
            .first()
            .map(|tool| {
                if tool.exposed.starts_with(KIN_TOOL_PREFIX) {
                    KIN_TOOL_PREFIX
                } else {
                    tool.exposed
                        .rfind("__")
                        .map(|end| &tool.exposed[..end + 2])
                        .unwrap_or(KIN_TOOL_PREFIX)
                }
            })
            .unwrap_or(KIN_TOOL_PREFIX)
    }

    /// Whether a Kin tool, named as its server declares it, is on this belt.
    pub fn has_kin_tool(&self, bare: &str) -> bool {
        self.kin_tools.iter().any(|tool| tool.bare == bare)
    }

    /// Every callable name, which is also what the text-shape parsers match against.
    pub fn names(&self) -> &BTreeSet<String> {
        &self.names
    }

    /// The schema a named tool declares, for argument validation.
    pub fn schema_for(&self, name: &str) -> Option<Value> {
        if let Some(tool) = self.kin_tools.iter().find(|tool| tool.exposed == name) {
            return Some(tool.schema.clone());
        }
        if self.file_tools {
            match name {
                EDIT_FILE => return Some(edit_file_schema()),
                WRITE_FILE => return Some(write_file_schema()),
                _ => {}
            }
        }
        None
    }

    /// Route a name the model produced, ignoring arguments.
    ///
    /// A folded tool takes its default half here, because a name on its own
    /// cannot say which half a call meant. The dispatcher calls
    /// [`Belt::route_call`] instead, which has the arguments.
    pub fn route(&self, name: &str) -> Route {
        self.route_call(name, &Value::Null).route
    }

    /// Route a name the model produced, with the arguments it sent, and say what
    /// goes out on the wire.
    ///
    /// The arguments change the destination for exactly one belt tool, the
    /// folded traversal tool, and they are rewritten for that one alone. Every
    /// other call goes out with the arguments the model wrote, byte for byte, so
    /// a trace row and a refusal keep naming what the model actually sent.
    pub fn route_call(&self, name: &str, arguments: &Value) -> RoutedCall {
        if let Some(tool) = self.kin_tools.iter().find(|tool| tool.exposed == name) {
            if tool.folded {
                let (bare, arguments) = resolve_trace_call(arguments);
                return RoutedCall {
                    route: Route::Kin {
                        server: tool.server,
                        tool: bare.to_string(),
                    },
                    arguments,
                };
            }
            return RoutedCall {
                route: Route::Kin {
                    server: tool.server,
                    tool: tool.bare.clone(),
                },
                arguments: arguments.clone(),
            };
        }
        RoutedCall {
            route: self.route_by_name(name),
            arguments: arguments.clone(),
        }
    }

    /// Everything routing does once a Kin tool has been ruled out.
    fn route_by_name(&self, name: &str) -> Route {
        if self.file_tools {
            match name {
                EDIT_FILE => return Route::Local(LocalTool::Edit),
                WRITE_FILE => return Route::Local(LocalTool::Write),
                _ => {}
            }
        } else if name == EDIT_FILE || name == WRITE_FILE {
            return Route::Refused(format!(
                "There is no tool named `{name}` on this belt. This agent is locked to Kin tools only. \
                 To mutate code in the repository, call `{}kin_mutate` with an operations array \
                 naming the entity and new source body.",
                self.kin_prefix()
            ));
        }
        // A bare Kin tool name is a near miss worth naming precisely, because the model
        // very likely meant a prefixed one and a generic refusal would not say so. With
        // several repositories attached the same bare name exists on each, so the refusal
        // names every prefixed form rather than picking one for the model.
        let candidates: Vec<String> = self
            .kin_tools
            .iter()
            .filter(|tool| tool.bare == name)
            .map(|tool| format!("`{}`", tool.exposed))
            .collect();
        if !candidates.is_empty() {
            return Route::Refused(format!(
                "There is no tool named `{name}`. The Kin tool is called {}. Call it by that \
                 exact name.",
                candidates.join(" or ")
            ));
        }
        Route::Refused(format!(
            "There is no tool named `{name}` and it will not be run. This agent has no shell, \
             no file-search and no file-read tool on purpose: repository questions are answered \
             from the Kin graph, not from the filesystem. Available tools: {}.",
            self.names.iter().cloned().collect::<Vec<_>>().join(", ")
        ))
    }

    /// The `tools` array sent to the chat endpoint.
    ///
    /// `repo_note` is appended to the two local tool descriptions when a run attached more
    /// than one repository, because the path rule genuinely changes: a relative path can no
    /// longer mean only one tree.
    pub fn to_specs(&self, repo_note: Option<&str>) -> Vec<Value> {
        let mut specs = Vec::new();
        for tool in &self.kin_tools {
            specs.push(json!({
                "type": "function",
                "function": {
                    "name": tool.exposed,
                    "description": tool.description,
                    "parameters": tool.schema,
                }
            }));
        }
        if self.file_tools {
            let suffix = match repo_note {
                Some(note) => format!(" {note}"),
                None => String::new(),
            };
            specs.push(json!({
                "type": "function",
                "function": {
                    "name": EDIT_FILE,
                    "description": format!(
                        "Replace one exact snippet of text in one file. `find` is matched byte for \
                         byte, including indentation, and must appear exactly once unless \
                         `replace_all` is true. When the thing you are changing IS an entity Kin \
                         has already named for you, a function, a method or a class, prefer \
                         `{prefix}kin_mutate` with one operation {{\"verb\": \"update\", \
                         \"target\": \"<that entity id>\", \"body\": \"<its complete new \
                         source>\", \"description\": \"...\"}}: it names the change and needs \
                         no old bytes at all. Use this tool for a change smaller than an entity, \
                         or in a file the graph holds no entity for.{suffix}",
                        prefix = self.kin_prefix(),
                    ),
                    "parameters": edit_file_schema(),
                }
            }));
            specs.push(json!({
                "type": "function",
                "function": {
                    "name": WRITE_FILE,
                    "description": format!(
                        "Write a file in full, creating it if it does not exist. Use this for a new \
                         file; an existing one is changed through `{edit}` or, when the change is a \
                         whole entity, through `{prefix}kin_mutate`.{suffix}",
                        edit = EDIT_FILE,
                        prefix = self.kin_prefix(),
                    ),
                    "parameters": write_file_schema(),
                }
            }));
        }
        specs
    }
}

fn edit_file_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Repository-relative path of the file to change." },
            "find": { "type": "string", "description": "The exact text to replace, including indentation." },
            "replace": { "type": "string", "description": "The exact text to put in its place." },
            "replace_all": { "type": "boolean", "description": "Replace every occurrence instead of requiring exactly one.", "default": false }
        },
        "required": ["path", "find", "replace"]
    })
}

fn write_file_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Repository-relative path of the file to write." },
            "content": { "type": "string", "description": "The file's complete new UTF-8 contents." }
        },
        "required": ["path", "content"]
    })
}

/// A bounded schema check: required properties present, and declared scalar types honored.
///
/// It deliberately stops short of full JSON Schema. What it catches is the failure that
/// actually happens with small local models, which is a missing required argument or a
/// number sent as prose, and it names the offending field so the repair turn can be
/// specific. It is not a validity proof and nothing here should be read as one.
pub fn validate_arguments(schema: &Value, arguments: &Value) -> Result<(), String> {
    let Some(object) = arguments.as_object() else {
        return Err("the arguments were not a JSON object".to_string());
    };
    let mut problems = Vec::new();

    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for field in required {
            let Some(name) = field.as_str() else { continue };
            match object.get(name) {
                None | Some(Value::Null) => {
                    problems.push(format!("required argument `{name}` was missing"))
                }
                Some(Value::String(text)) if text.is_empty() => {
                    problems.push(format!("required argument `{name}` was an empty string"))
                }
                _ => {}
            }
        }
    }

    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, value) in object {
            if name.starts_with("__kin_agent_") {
                continue;
            }
            let Some(declared) = properties.get(name).and_then(|p| p.get("type")) else {
                continue;
            };
            let Some(expected) = declared.as_str() else {
                continue;
            };
            if !type_matches(expected, value) {
                problems.push(format!(
                    "argument `{name}` should be a {expected} but was {}",
                    describe(value)
                ));
            }
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn describe(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "a string",
        Value::Number(_) => "a number",
        Value::Bool(_) => "a boolean",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
        Value::Null => "null",
    }
}

/// What a local tool did, or why it did not.
#[derive(Debug, Clone)]
pub struct LocalOutcome {
    pub text: String,
    pub is_error: bool,
    /// The repository-relative path that changed, when one did.
    pub changed: Option<String>,
    /// The file's complete new text, as this tool left it.
    ///
    /// Repository authority admits a source change from the whole file, so the harness
    /// has to hand it those bytes. It carries them out of the tool that produced them
    /// rather than reading the file back: the text is already in hand here, a read would
    /// put a filesystem access on the runtime path, and between the write and the read
    /// the file could be something else.
    pub body: Option<String>,
    /// Set on a refusal the model can clear by sending different bytes for the same
    /// target, which is the only refusal re-reading the source answers.
    ///
    /// The repeat guard counts these per target and only these. An edit repository
    /// authority declined to publish is a different problem with a different answer,
    /// and a run redirected to go and re-read source over one is told the wrong thing.
    pub retry_with_bytes: bool,
}

/// Resolve a model-supplied path inside the repository, refusing every escape.
///
/// A harness with no shell tool has exactly two write surfaces, and if either can be
/// pointed outside the repository then the sandbox is decorative.
pub fn resolve_in_repo(repo: &Path, raw: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(raw);
    let relative = if candidate.is_absolute() {
        match candidate.strip_prefix(repo) {
            Ok(rest) => rest.to_path_buf(),
            Err(_) => {
                return Err(format!(
                    "`{raw}` is outside the repository at {}. Paths must be repository-relative.",
                    repo.display()
                ))
            }
        }
    } else {
        candidate.to_path_buf()
    };

    let mut resolved = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "`{raw}` walks out of the repository with `..`, which is refused."
                ))
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("`{raw}` is not a repository-relative path."))
            }
        }
    }
    if resolved.as_os_str().is_empty() {
        return Err("the path was empty".to_string());
    }
    Ok(repo.join(resolved))
}

/// Resolve a model-supplied path to the repository that owns it, and to the file inside it.
///
/// One repository is the ordinary case and behaves exactly like [`resolve_in_repo`]. With
/// several attached, an absolute path is matched against every root and the longest match
/// wins, which is the containment rule and the only one that stays correct when one
/// checkout sits inside another. A relative path resolves against the primary repository,
/// because the alternative is asking the filesystem which tree the model meant, and a wrong
/// guess writes into the wrong repository. The model is told this rule in the tool
/// descriptions rather than left to discover it.
pub fn resolve_across_repos(repos: &[PathBuf], raw: &str) -> Result<(usize, PathBuf), String> {
    let Some(primary) = repos.first() else {
        return Err("this run attached no repository".to_string());
    };
    if repos.len() == 1 || !Path::new(raw).is_absolute() {
        return resolve_in_repo(primary, raw).map(|path| (0, path));
    }
    let mut best: Option<(usize, PathBuf, usize)> = None;
    for (index, repo) in repos.iter().enumerate() {
        let Ok(path) = resolve_in_repo(repo, raw) else {
            continue;
        };
        let depth = repo.components().count();
        let better = match &best {
            None => true,
            Some((_, _, chosen)) => depth > *chosen,
        };
        if better {
            best = Some((index, path, depth));
        }
    }
    match best {
        Some((index, path, _)) => Ok((index, path)),
        None => Err(format!(
            "`{raw}` is outside every repository this run attached. The roots are: {}.",
            repos
                .iter()
                .map(|repo| repo.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// An `edit_file` call resolved against the file's current text, before anything is written.
///
/// The harness publishes an edit through repository authority, and authority's projection is
/// what writes the file, so the edit is computed here and handed to the stage as the file's
/// complete new text instead of being applied to the working copy first.
#[derive(Debug, Clone)]
pub struct PlannedEdit {
    /// The path as the model wrote it, for the messages the model reads.
    pub raw_path: String,
    /// The resolved path inside the repository.
    pub path: PathBuf,
    /// How many occurrences the edit replaces.
    pub replaced: usize,
    /// The file's length before the edit, in bytes.
    pub before_len: usize,
    /// The file's complete new text.
    pub updated: String,
}

impl PlannedEdit {
    /// What the edit does, without saying whether it landed.
    fn summary(&self) -> String {
        format!(
            "Edited `{}`: replaced {} occurrence{} ({} bytes before, {} after)",
            self.raw_path,
            self.replaced,
            if self.replaced == 1 { "" } else { "s" },
            self.before_len,
            self.updated.len()
        )
    }
}

/// Run `edit_file` on the working copy directly.
///
/// This is the path for an edit no transaction brackets. A bracketed edit is planned with
/// [`plan_edit`] and published through repository authority, which writes the file itself.
pub fn run_edit(repo: &Path, arguments: &Value) -> LocalOutcome {
    let planned = match plan_edit(repo, arguments) {
        Ok(planned) => planned,
        Err(refusal) => return refusal,
    };
    if let Err(err) = std::fs::write(&planned.path, &planned.updated) {
        return LocalOutcome::error(format!("could not write `{}`: {err}", planned.raw_path));
    }
    LocalOutcome {
        text: format!("{}.", planned.summary()),
        is_error: false,
        changed: Some(planned.raw_path.clone()),
        body: Some(planned.updated),
        retry_with_bytes: false,
    }
}

/// The outcome of an `edit_file` whose change repository authority published for us.
///
/// The new text reached the working copy through the commit rather than through this
/// process, so nothing is written here; the model is told what landed and who wrote it.
pub fn published_edit(planned: PlannedEdit) -> LocalOutcome {
    LocalOutcome {
        text: format!(
            "{} and published it through repository authority, which wrote the file.",
            planned.summary()
        ),
        is_error: false,
        changed: Some(planned.raw_path.clone()),
        body: Some(planned.updated),
        retry_with_bytes: false,
    }
}

/// The outcome of an `edit_file` repository authority did not publish.
///
/// Nothing was written. The edit exists only in the model's own call, the working copy and
/// the graph both still hold the file as it was, and the model is told so, with the server's
/// reason, so it can correct the cause and send the edit again.
pub fn unpublished_edit(planned: &PlannedEdit, reason: &str) -> LocalOutcome {
    LocalOutcome::error(format!(
        "The edit of `{path}` did not land: repository authority did not publish it: {reason}. \
         Nothing was written, so `{path}` is unchanged on disk and in the graph. Correct the \
         cause and send the edit again.",
        path = planned.raw_path,
    ))
}

/// How many lines of the file a refusal quotes back.
///
/// Six covers a signature and the guard clause under it, which is the span a surgical
/// change names, and stops a refusal on a long `find` from returning a page of source the
/// run already paid to read once.
const REFUSAL_QUOTE_LINES: usize = 6;

/// How many bytes of the file a refusal quotes back.
const REFUSAL_QUOTE_BYTES: usize = 400;

/// The markers a refusal wraps quoted bytes in.
///
/// Not a Markdown fence. Source carries backticks, and a model that has to guess where the
/// quoted text stops is the failure this message exists to prevent.
const QUOTE_OPEN: &str = "<<<KIN-EXACT";
const QUOTE_CLOSE: &str = ">>>KIN-EXACT";

/// Why a `find` did not match, and the bytes in the file it points at instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchMiss {
    /// What went wrong, in the model's terms.
    pub reason: String,
    /// The file's exact current bytes over the span the refusal points at.
    pub bytes: String,
    /// 1-based and inclusive, so a reader can join this to a source listing.
    pub first_line: usize,
    pub last_line: usize,
    /// Set when `bytes` is the whole span and re-sending it verbatim must match. Clear
    /// when the span was cut to the quote bound, or when nothing matched and the bytes
    /// are the nearest text rather than a proven substitute.
    pub verbatim: bool,
}

/// Decode the two-character escape sequences a model writes when it escapes its JSON twice.
///
/// This is the measured failure, not a hypothetical one. `get_entity_source` returns the
/// source inside a JSON result, so a tab in the file reaches the model as the two
/// characters `\` and `t`. A model that copies what it read into the next call's `find`
/// sends those two characters, the file holds one tab, and the byte comparison is right to
/// refuse. Returns `None` when there was nothing to decode, so the caller does not test the
/// same candidate twice.
fn decode_literal_escapes(text: &str) -> Option<String> {
    if !text.contains('\\') {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut characters = text.chars();
    let mut decoded_any = false;
    while let Some(character) = characters.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match characters.next() {
            Some('n') => {
                out.push('\n');
                decoded_any = true;
            }
            Some('t') => {
                out.push('\t');
                decoded_any = true;
            }
            Some('r') => {
                out.push('\r');
                decoded_any = true;
            }
            Some('"') => {
                out.push('"');
                decoded_any = true;
            }
            Some('\'') => {
                out.push('\'');
                decoded_any = true;
            }
            Some('\\') => {
                out.push('\\');
                decoded_any = true;
            }
            // Not an escape this decoder knows, so it is left exactly as the model wrote
            // it and a Windows path or a regex in the source is never quietly rewritten.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    decoded_any.then_some(out)
}

/// The 1-based line a byte offset falls on.
fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

/// A span cut to the quote bound, and whether it survived whole.
fn quote_span(span: &str) -> (String, bool) {
    let mut kept = String::new();
    let mut whole = true;
    for (index, line) in span.split_inclusive('\n').enumerate() {
        if index >= REFUSAL_QUOTE_LINES || kept.len() + line.len() > REFUSAL_QUOTE_BYTES {
            whole = false;
            break;
        }
        kept.push_str(line);
    }
    if kept.is_empty() {
        // One line longer than the whole bound. Cut rather than return nothing: a prefix
        // of the real bytes still shows the model where its own text went wrong.
        let mut end = REFUSAL_QUOTE_BYTES.min(span.len());
        while end > 0 && !span.is_char_boundary(end) {
            end -= 1;
        }
        return (span[..end].to_string(), false);
    }
    (kept, whole)
}

/// The miss a matching candidate produced, described against the file's own span.
fn miss_at(original: &str, offset: usize, matched_len: usize, reason: &str) -> MatchMiss {
    let end = (offset + matched_len).min(original.len());
    let span = &original[offset..end];
    let (bytes, whole) = quote_span(span);
    let first_line = line_of(original, offset);
    // Counted forward through the span rather than by looking up the line of its last
    // byte. `end - 1` is inside the final character whenever that character is not
    // ASCII, and slicing there panics. A span closing on a newline ends on the line
    // that newline terminates, not the empty one after it.
    let lines_spanned = span
        .strip_suffix('\n')
        .unwrap_or(span)
        .matches('\n')
        .count();
    MatchMiss {
        reason: reason.to_string(),
        first_line,
        last_line: first_line + lines_spanned,
        bytes,
        verbatim: whole,
    }
}

/// The alphanumeric words of a line, for the nearest-line measure.
fn line_words(line: &str) -> Vec<String> {
    line.split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase())
        .collect()
}

/// The byte offset a 0-based line starts at, in a text split on `\n`.
fn offset_of_line(lines: &[&str], line: usize) -> usize {
    lines[..line].iter().map(|line| line.len() + 1).sum()
}

/// Why a `find` did not match this file, and the bytes that would have.
///
/// Candidates are tried in the order of how cheaply the model can act on the answer. One
/// that matches gives an exact span, so the refusal hands back bytes proven to match
/// rather than a guess. When none matches, the nearest line by shared words is the anchor,
/// and the refusal says those bytes are the nearest text rather than a substitute.
///
/// Nothing here rewrites the edit. A decoder that quietly accepted the model's escaped form
/// would apply a change to bytes the model never named, and a file that genuinely holds a
/// literal backslash-t would be corrupted by it. The decoding only ever explains.
pub fn diagnose_miss(original: &str, find: &str) -> Option<MatchMiss> {
    if find.is_empty() || original.is_empty() {
        return None;
    }
    let decoded = decode_literal_escapes(find);
    let mut candidates: Vec<(String, &str)> = Vec::new();
    if find.contains('\r') {
        candidates.push((
            find.replace("\r\n", "\n").replace('\r', ""),
            "the text carried carriage returns this file does not have",
        ));
    }
    if let Some(decoded) = decoded.clone() {
        candidates.push((
            decoded.clone(),
            "the text arrived with its escape sequences literal, so `\\n`, `\\t` and `\\\"` reached \
             this tool as backslash characters instead of a newline, a tab and a quote. Source read \
             out of a JSON result is already escaped once, and has to be written back as the \
             characters themselves",
        ));
        if decoded.contains('\r') {
            candidates.push((
                decoded.replace("\r\n", "\n").replace('\r', ""),
                "the text arrived with its escape sequences literal and carried carriage returns \
                 this file does not have",
            ));
        }
    }
    for (candidate, reason) in &candidates {
        if let Some(offset) = original.find(candidate.as_str()) {
            return Some(miss_at(original, offset, candidate.len(), reason));
        }
    }

    // The same lines with different surrounding whitespace. Reported against the file's own
    // lines, because those are the bytes the model has to send.
    let probe_source = decoded.as_deref().unwrap_or(find);
    let probe: Vec<&str> = probe_source.trim_end_matches('\n').split('\n').collect();
    let lines: Vec<&str> = original.split('\n').collect();
    if probe.iter().any(|line| !line.trim().is_empty()) && probe.len() <= lines.len() {
        let window = probe.len();
        let hit = (0..=lines.len() - window).find(|start| {
            lines[*start..start + window]
                .iter()
                .zip(&probe)
                .all(|(have, want)| have.trim() == want.trim())
        });
        if let Some(start) = hit {
            let offset = offset_of_line(&lines, start);
            let span: usize = lines[start..start + window]
                .iter()
                .map(|line| line.len() + 1)
                .sum();
            let reason = if decoded.is_some() {
                "the text arrived with its escape sequences literal, and its indentation is not the \
                 file's either"
            } else {
                "these lines are in the file, but their leading or trailing whitespace is not what \
                 was sent. Indentation is part of the bytes"
            };
            return Some(miss_at(original, offset, span, reason));
        }
    }

    // Nothing matched under any reading. Anchor on the nearest line so the refusal still
    // hands back current bytes, and say plainly what they are.
    let first_probe = probe.iter().find(|line| !line.trim().is_empty())?;
    let wanted = line_words(first_probe);
    if wanted.is_empty() {
        return None;
    }
    let (best, score) = lines
        .iter()
        .enumerate()
        .fold((0usize, 0.0f64), |best, (index, line)| {
            let have = line_words(line);
            if have.is_empty() {
                return best;
            }
            let shared = wanted.iter().filter(|word| have.contains(word)).count() as f64;
            let ratio = shared / wanted.len().max(have.len()) as f64;
            if ratio > best.1 {
                (index, ratio)
            } else {
                best
            }
        });
    if score <= 0.0 {
        return None;
    }
    let offset = offset_of_line(&lines, best);
    let window = probe
        .len()
        .clamp(1, REFUSAL_QUOTE_LINES)
        .min(lines.len() - best);
    let span: usize = lines[best..best + window]
        .iter()
        .map(|line| line.len() + 1)
        .sum();
    let mut miss = miss_at(
        original,
        offset,
        span,
        "no text in the file matches what was sent, under any reading of it. Either the read it \
         came from is stale, or it names a different line than the one intended",
    );
    miss.verbatim = false;
    Some(miss)
}

/// The one route to the same change that needs no old bytes at all.
///
/// Named in every unmatched refusal, because a model that cannot make a byte match work
/// has a second way to the same edit and the measured run shows it does not remember that
/// on its own.
fn entity_named_route() -> String {
    format!(
        "To change a whole function, method or class without matching any old text, call \
         `{KIN_TOOL_PREFIX}kin_mutate` with operations [{{\"verb\": \"update\", \"target\": \
         \"<the entity id {KIN_TOOL_PREFIX}semantic_locate gave you>\", \"body\": \"<the entity's \
         complete new source>\", \"description\": \"...\"}}]."
    )
}

/// What the model is told when its `find` matched nothing.
///
/// A refusal that names only the failure is the defect this replaced. Measured on
/// 2026-09-15, `qwen/qwen3-coder-next` sent a `find` whose escape sequences were literal,
/// was told only that the text did not appear, and spent its remaining sixteen tool calls
/// on graph questions without attempting the change again. So this carries the three things
/// a retry needs and nothing else: why it did not match, the file's exact current bytes at
/// the closest span, and the one instruction that uses them.
fn unmatched_find(raw_path: &str, original: &str, find: &str) -> String {
    let Some(miss) = diagnose_miss(original, find) else {
        return format!(
            "the `find` text does not appear in `{raw_path}`, and no text in the file resembles it. \
             Read the entity's current source with {KIN_TOOL_PREFIX}get_entity_source and send \
             `find` as bytes that are in the file. {}",
            entity_named_route()
        );
    };
    let lines = if miss.first_line == miss.last_line {
        format!("line {}", miss.first_line)
    } else {
        format!("lines {} to {}", miss.first_line, miss.last_line)
    };
    let quoted = miss.bytes.trim_end_matches('\n');
    let instruction = if miss.verbatim {
        "Re-issue this call with `find` set to exactly those bytes, and write `replace` the same \
         way."
    } else {
        "Those are the file's current bytes, cut to a few lines, and not a substitute for what was \
         sent. Take a short unique snippet out of them and re-issue this call with `find` set to \
         it, written exactly as it appears there."
    };
    format!(
        "the `find` text does not appear in `{raw_path}`. Why it did not match: {reason}. The \
         file's exact current bytes at {lines} are between the markers below.\n\
         {QUOTE_OPEN}\n{quoted}\n{QUOTE_CLOSE}\n\
         {instruction} {route}",
        reason = miss.reason,
        route = entity_named_route(),
    )
}

/// Resolve an `edit_file` call against the file's current text without writing anything.
pub fn plan_edit(repo: &Path, arguments: &Value) -> Result<PlannedEdit, LocalOutcome> {
    let raw_path = arguments.get("path").and_then(Value::as_str).unwrap_or("");
    let find = arguments.get("find").and_then(Value::as_str).unwrap_or("");
    let replace = arguments
        .get("replace")
        .and_then(Value::as_str)
        .unwrap_or("");
    let replace_all = arguments
        .get("replace_all")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let path = resolve_in_repo(repo, raw_path).map_err(LocalOutcome::error)?;
    let original = std::fs::read_to_string(&path).map_err(|err| {
        LocalOutcome::error(format!(
            "could not read `{raw_path}`: {err}. Use Kin to find the file before editing it."
        ))
    })?;
    let occurrences = original.matches(find).count();
    if occurrences == 0 {
        return Err(LocalOutcome::retry_with_bytes(unmatched_find(
            raw_path, &original, find,
        )));
    }
    if occurrences > 1 && !replace_all {
        return Err(LocalOutcome::retry_with_bytes(format!(
            "the `find` text appears {occurrences} times in `{raw_path}`. Give a longer, unique \
             snippet, or set replace_all to true if every occurrence should change."
        )));
    }
    let updated = if replace_all {
        original.replace(find, replace)
    } else {
        original.replacen(find, replace, 1)
    };
    Ok(PlannedEdit {
        raw_path: raw_path.to_string(),
        path,
        replaced: if replace_all { occurrences } else { 1 },
        before_len: original.len(),
        updated,
    })
}

/// Run `write_file`.
pub fn run_write(repo: &Path, arguments: &Value) -> LocalOutcome {
    let raw_path = arguments.get("path").and_then(Value::as_str).unwrap_or("");
    let content = arguments
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("");
    let path = match resolve_in_repo(repo, raw_path) {
        Ok(path) => path,
        Err(message) => return LocalOutcome::error(message),
    };
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            return LocalOutcome::error(format!("could not create `{}`: {err}", parent.display()));
        }
    }
    let existed = path.exists();
    if let Err(err) = std::fs::write(&path, content) {
        return LocalOutcome::error(format!("could not write `{raw_path}`: {err}"));
    }
    LocalOutcome {
        text: format!(
            "{} `{raw_path}` ({} bytes).",
            if existed { "Rewrote" } else { "Created" },
            content.len()
        ),
        is_error: false,
        changed: Some(raw_path.to_string()),
        body: Some(content.to_string()),
        retry_with_bytes: false,
    }
}

/// The outcome of a `write_file` whose file repository authority published for us.
///
/// The bytes reached the working copy through the commit rather than through this process,
/// so nothing is written here; the model is told what landed and where.
pub fn published_create(arguments: &Value) -> LocalOutcome {
    let raw_path = arguments.get("path").and_then(Value::as_str).unwrap_or("");
    let content = arguments
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("");
    LocalOutcome {
        text: format!(
            "Created `{raw_path}` ({} bytes) and published it through repository authority, \
             which wrote the file.",
            content.len()
        ),
        is_error: false,
        changed: Some(raw_path.to_string()),
        body: Some(content.to_string()),
        retry_with_bytes: false,
    }
}

/// The outcome of a `write_file` repository authority did not publish.
///
/// Nothing is written, so the path stays exactly as it was on disk and in the graph. The
/// refused content comes back in the result, which is where the model keeps its work: a
/// copy left on disk was a file the graph did not hold, the same split a refused edit left.
pub fn unpublished_create(arguments: &Value, reason: &str) -> LocalOutcome {
    let raw_path = arguments.get("path").and_then(Value::as_str).unwrap_or("");
    let content = arguments
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("");
    LocalOutcome::error(format!(
        "`{raw_path}` was not created: repository authority did not publish it: {reason}. \
         Nothing was written, so `{raw_path}` is unchanged on disk and in the graph. The {} \
         bytes you sent follow, so you can correct the cause and send them again:\n{content}",
        content.len()
    ))
}

/// The outcome of an `edit_file` or `write_file` for which Kin could not open a transaction.
///
/// Kin is attached, so the change belongs in the graph, and without a transaction it cannot
/// get there. Nothing is written: a local write here would be a change on disk the graph
/// never hears about. The model is told why, in the server's words.
pub fn unbracketed_refusal(arguments: &Value, reason: &str) -> LocalOutcome {
    let raw_path = arguments.get("path").and_then(Value::as_str).unwrap_or("");
    LocalOutcome::error(format!(
        "`{raw_path}` was not changed: Kin could not open a transaction for this change: \
         {reason}. Nothing was written, so `{raw_path}` is unchanged on disk and in the graph."
    ))
}

impl LocalOutcome {
    /// A refusal the model is handed instead of a run, in the shape a run would have
    /// produced, so a routing failure reads to the caller exactly like a tool failure.
    pub fn error(message: String) -> Self {
        LocalOutcome {
            text: message,
            is_error: true,
            changed: None,
            body: None,
            retry_with_bytes: false,
        }
    }

    /// A refusal the model clears by sending different bytes for the same target.
    ///
    /// Only the two byte-matching refusals use this. It is what the repeat guard counts,
    /// so widening it to every failed change would redirect a run to re-read source over
    /// a commit repository authority declined, which re-reading does not fix.
    pub fn retry_with_bytes(message: String) -> Self {
        LocalOutcome {
            retry_with_bytes: true,
            ..LocalOutcome::error(message)
        }
    }
}

/// Strip Kin tools the harness drives itself out of the model's belt.
///
/// Session and transaction lifecycle is the harness's job, so exposing those tools would
/// let the model open a second session or commit a transaction the harness is holding.
///
/// `kin_transaction_stage` and `kin_transaction_validate` belong on this list for a
/// sharper reason than tidiness. Both require a transaction id, and `kin_transaction_begin`
/// is the only way to get one honestly. A model holding stage without begin cannot obtain
/// an id at all, so its only remaining move is to invent one, which is what an observed
/// local-model run did before the harness staged on its own behalf. Hiding the whole set
/// is what makes the harness the single writer.
pub fn is_harness_owned(name: &str) -> bool {
    matches!(
        name,
        "kin_session_start"
            | "kin_session_end"
            | "kin_session_heartbeat"
            | "kin_transaction_begin"
            | "kin_transaction_stage"
            | "kin_transaction_validate"
            | "kin_transaction_commit"
            | "kin_transaction_abort"
    )
}

/// Empty map, for calls that take no arguments.
pub fn empty_arguments() -> Value {
    Value::Object(Map::new())
}
