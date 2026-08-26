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

/// The belt: every name the model may call this run.
#[derive(Debug, Clone)]
pub struct Belt {
    kin_tools: Vec<KinTool>,
    names: BTreeSet<String>,
}

impl Belt {
    /// Build the belt from what the MCP servers declared, plus the two local tools.
    pub fn new(kin_tools: Vec<KinTool>) -> Self {
        let mut names: BTreeSet<String> =
            kin_tools.iter().map(|tool| tool.exposed.clone()).collect();
        names.insert(EDIT_FILE.to_string());
        names.insert(WRITE_FILE.to_string());
        Belt { kin_tools, names }
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
        match name {
            EDIT_FILE => Some(edit_file_schema()),
            WRITE_FILE => Some(write_file_schema()),
            _ => None,
        }
    }

    /// Route a name the model produced.
    pub fn route(&self, name: &str) -> Route {
        if let Some(tool) = self.kin_tools.iter().find(|tool| tool.exposed == name) {
            return Route::Kin {
                server: tool.server,
                tool: tool.bare.clone(),
            };
        }
        match name {
            EDIT_FILE => return Route::Local(LocalTool::Edit),
            WRITE_FILE => return Route::Local(LocalTool::Write),
            _ => {}
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
        let suffix = match repo_note {
            Some(note) => format!(" {note}"),
            None => String::new(),
        };
        specs.push(json!({
            "type": "function",
            "function": {
                "name": EDIT_FILE,
                "description": format!(
                    "Replace one exact snippet of text in one file. The `find` text must appear \
                     exactly once in the file unless `replace_all` is true. Use this for a small, \
                     surgical change once Kin has told you where the code is.{suffix}"
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
                     file; prefer edit_file for a change to an existing one.{suffix}"
                ),
                "parameters": write_file_schema(),
            }
        }));
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

/// Run `edit_file`.
pub fn run_edit(repo: &Path, arguments: &Value) -> LocalOutcome {
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

    let path = match resolve_in_repo(repo, raw_path) {
        Ok(path) => path,
        Err(message) => return LocalOutcome::error(message),
    };
    let original = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            return LocalOutcome::error(format!(
                "could not read `{raw_path}`: {err}. Use Kin to find the file before editing it."
            ))
        }
    };
    let occurrences = original.matches(find).count();
    if occurrences == 0 {
        return LocalOutcome::error(format!(
            "the `find` text does not appear in `{raw_path}`. Read the exact current text with \
             {KIN_TOOL_PREFIX}get_entity_source before editing, and match it byte for byte."
        ));
    }
    if occurrences > 1 && !replace_all {
        return LocalOutcome::error(format!(
            "the `find` text appears {occurrences} times in `{raw_path}`. Give a longer, unique \
             snippet, or set replace_all to true if every occurrence should change."
        ));
    }
    let updated = if replace_all {
        original.replace(find, replace)
    } else {
        original.replacen(find, replace, 1)
    };
    if let Err(err) = std::fs::write(&path, &updated) {
        return LocalOutcome::error(format!("could not write `{raw_path}`: {err}"));
    }
    LocalOutcome {
        text: format!(
            "Edited `{raw_path}`: replaced {} occurrence{} ({} bytes before, {} after).",
            if replace_all { occurrences } else { 1 },
            if replace_all && occurrences != 1 {
                "s"
            } else {
                ""
            },
            original.len(),
            updated.len()
        ),
        is_error: false,
        changed: Some(raw_path.to_string()),
        body: Some(updated),
    }
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
    }
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
