// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The toolbelt and the router that enforces it.
//!
//! The policy is enforced by absence and by refusal. The belt carries Kin tools and
//! nothing else: there is no shell tool, no file-read, file-search or file-write tool
//! anywhere in it, so there is nothing to fall back to, and the router refuses by name any
//! tool the model invents. Both halves matter: a model that hallucinates a `bash` tool must
//! be told no rather than quietly handed an empty result it will read as "the command
//! produced nothing".

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::path::Path;

/// Prefix that marks a Kin tool in the model's belt and in the transcript. `usage.py`
/// classifies `mcp__<server>__<tool>` as an MCP call, so this is what makes a Kin call
/// countable by the analyzers the fleet already runs.
pub const KIN_TOOL_PREFIX: &str = "mcp__kin__";

/// Where a routed call goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// A Kin tool, named without the transcript prefix, on the server that serves it.
    Kin { server: usize, tool: String },
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

/// How much of the server's surface this run puts on the model's belt.
///
/// The server's `agent-default` profile is curated for a client with room. A
/// local model's window is the binding constraint, and measured on
/// `qwen/qwen3.8-27b` the fifteen Kin tools plus the two local file tools the belt
/// then carried cost 6,367 prompt tokens before the model had read one line of code. Four of those tools
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

/// Optional metadata and traversal tools on the wider belt.
/// Whole-artifact source reading is retired, not an opt-in capability.
pub fn is_opt_in(name: &str) -> bool {
    matches!(name, "graph_neighborhood" | "kin_provenance_query")
}

/// File catalogs and whole-artifact reads stay retired even if an older server
/// advertises them or a wider profile is selected.
fn is_retired_file_operation(name: &str) -> bool {
    matches!(
        name,
        "kin_artifact_read" | "kin_artifact_list" | "list_file_entities"
    )
}

// Match the routed MCP command spelling: optional `kin ` prefix, case folding,
// and spaces/hyphens as underscore separators. Registered direct names are exact.
fn normalized_routed_command(raw: &str) -> String {
    let command = raw.trim().to_ascii_lowercase();
    let command = command.strip_prefix("kin ").unwrap_or(&command).trim();
    let mut normalized = String::new();
    let mut separator = false;
    for character in command.chars() {
        if character == '-' || character.is_whitespace() {
            if !separator {
                normalized.push('_');
            }
            separator = true;
        } else {
            normalized.push(character);
            separator = false;
        }
    }
    normalized
}

fn calls_retired_file_operation(tool: &str, arguments: &Value) -> bool {
    match tool {
        "kin_tool_call" => arguments
            .get("tool")
            .and_then(Value::as_str)
            .is_some_and(is_retired_file_operation),
        "kin" => {
            let command = normalized_routed_command(
                arguments
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            let target = if command == "call" || command == "describe" {
                let property = if command == "call" { "tool" } else { "command" };
                normalized_routed_command(
                    arguments
                        .get("args")
                        .and_then(|args| args.get(property))
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                )
            } else {
                command
            };
            target == "read" || is_retired_file_operation(&target)
        }
        _ => false,
    }
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
}

/// The values `KIN_AGENT_PURE_KIN` reads as off.
///
/// Exactly the set kin-core's env registry accepts as false for a `Kind::Bool`
/// (`BOOL_FALSE` in `kin-core/src/env_registry.rs`, where this variable is
/// registered), trimmed and case-folded the same way, so the switch means one
/// thing across the product. Mirrored rather than imported because kin-agent
/// takes no kin-core dependency.
const PURE_KIN_FALSE: [&str; 4] = ["0", "false", "no", "off"];

/// Whether a `KIN_AGENT_PURE_KIN` value asks for the Kin-only belt, which is
/// the only belt there is.
///
/// Unset reads as on, and so does every true value. A value in the registry's
/// false set asked for the local file tools, which are retired, so a run given
/// one refuses to start ([`refuse_file_tools`]) rather than quietly running a
/// belt the operator did not ask for. A value that is neither true nor false by
/// the registry's reading is reported by its startup validation, so a typo is
/// surfaced there rather than guessed at here, and it leaves the default.
pub fn pure_kin_requested(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(value) => !PURE_KIN_FALSE.contains(&value.trim().to_ascii_lowercase().as_str()),
    }
}

/// Refuse a `KIN_AGENT_PURE_KIN` value that asks for the retired file tools.
///
/// The error names the value the operator set, so the refusal reads back what
/// they wrote. Every other value, and no value at all, is `Ok`.
pub fn refuse_file_tools(value: Option<&str>) -> Result<(), String> {
    match value {
        Some(value) if !pure_kin_requested(Some(value)) => Err(format!(
            "KIN_AGENT_PURE_KIN={} no longer adds file tools: Kin agents change code through \
             entities, and the local file tools are retired. Unset KIN_AGENT_PURE_KIN, or set \
             it to true, to run.",
            value.trim()
        )),
        _ => Ok(()),
    }
}

impl Belt {
    /// Build the belt from what the MCP servers declared. It carries Kin tools
    /// and nothing else.
    pub fn new(mut kin_tools: Vec<KinTool>) -> Self {
        // A retained/older server can still advertise the retired leaf. Never
        // restore it through a wider profile or an alternate server prefix.
        kin_tools.retain(|tool| !is_retired_file_operation(&tool.bare));
        let names: BTreeSet<String> = kin_tools.iter().map(|tool| tool.exposed.clone()).collect();
        Belt { kin_tools, names }
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
        self.kin_tools
            .iter()
            .find(|tool| tool.exposed == name)
            .map(|tool| tool.schema.clone())
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
            if calls_retired_file_operation(&tool.bare, arguments) {
                return RoutedCall {
                    route: Route::Refused("File operations are unavailable on the agent belt. Find entities with semantic_search or semantic_locate and follow their relationships.".into()),
                    arguments: arguments.clone(),
                };
            }
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
        // The two retired file tools are the names a model most often reaches for
        // to change code, so the refusal says how a change is made instead, and it
        // names only a write tool this belt actually carries.
        if name == "edit_file" || name == "write_file" {
            let how = if self.has_kin_tool("kin_mutate") {
                format!(
                    "Every change goes through `{prefix}kin_mutate`, naming the entity by its \
                     UUID and carrying the exact source_base `{prefix}get_entity_source` \
                     returned for it. Prefer verb 'patch' with an EntitySourcePatch of exact \
                     anchored edits over sending the whole body; add a top-level function with \
                     verb 'create' and an EntityCreate payload, and delete one with verb \
                     'remove' and an EntityRemove payload, as the kin_mutate schema describes. \
                     There is no file creation. If the change needs something kin_mutate cannot \
                     make, stop and say so.",
                    prefix = self.kin_prefix()
                )
            } else {
                "This run carries no tool that changes code, so say exactly what the change is \
                 instead of making it."
                    .to_string()
            };
            return Route::Refused(format!(
                "There is no tool named `{name}` on this belt. This agent is locked to Kin tools \
                 only: it changes code through entities, and the local file tools are retired. \
                 {how}"
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
    pub fn to_specs(&self) -> Vec<Value> {
        self.kin_tools
            .iter()
            .map(|tool| {
                json!({
                    "type": "function",
                    "function": {
                        "name": tool.exposed,
                        "description": tool.description,
                        "parameters": tool.schema,
                    }
                })
            })
            .collect()
    }
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
/// leaves `kin_mutate`, which opens and commits its own transaction, as the one way a
/// change reaches the graph.
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
