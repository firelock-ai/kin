// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin_session_exec`: run the project's toolchain for an agent.
//!
//! An agent that reaches Kin alone, with no shell and no file tools, writes
//! code through entity operations and could not build, test or run it. This
//! tool closes that gap without opening a second way to read or write whole
//! files. It runs one toolchain command, as separate words and never through a
//! shell, inside a session workspace materialized from the session's current
//! graph head, and answers with the exit code, the elapsed time and bounded
//! output.
//!
//! Two guards hold it to Kin's model, and both are enforced here and in the
//! launcher rather than asked of the agent:
//!
//! * **What runs.** Only the project's toolchain entry points: the defaults for
//!   the languages the project is written in, and whatever the repository's
//!   `[execution.agent]` allow list adds. Shells, command runners, inline-code
//!   interpreters and file-dumping utilities are refused before anything runs,
//!   whatever the configuration says, because each of them is a way to read or
//!   write whole files.
//! * **What comes back.** When the command succeeds, the manifests and
//!   lockfiles it wrote, `go.mod` and `go.sum` for one, are admitted and
//!   recorded as a change by the session that ran it. Source it created,
//!   changed or removed is refused and reported, since code is written through
//!   entity operations; any other file is refused too; and build outputs are
//!   never admitted.
//!
//! This crate touches no filesystem and starts no process. The launcher hands
//! the server a [`SessionExecutor`] that materializes the workspace, detects
//! the project's languages, runs the command and closes the workspace out, the
//! way it hands `kin_init` a [`crate::RepoInitializer`]. Everything here is the
//! policy and the words: argument checks, command admission, output bounds and
//! the answer.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::types::{ToolAnnotations, ToolCallResult, ToolDefinition};

/// The tool's registered name.
pub const TOOL_NAME: &str = "kin_session_exec";

/// How long a command runs when the call names no timeout. Under the 60 s
/// per-call timeout common MCP clients use, so the answer arrives before the
/// client gives up on it.
pub const DEFAULT_TIMEOUT_SECS: u64 = 50;

/// The longest timeout a call may ask for.
pub const MAX_TIMEOUT_SECS: u64 = 600;

/// How many bytes of each of stdout and stderr come back when the call names
/// no bound.
pub const DEFAULT_OUTPUT_BYTES: u64 = 6_000;

/// The smallest and largest output bound a call may ask for. The largest keeps
/// both streams, escaped, inside the 45,000-character default response.
pub const MIN_OUTPUT_BYTES: u64 = 256;
pub const MAX_OUTPUT_BYTES: u64 = 16_000;

/// The most words one command may have.
pub const MAX_ARGV: u64 = 64;

/// The registered description.
pub const DESCRIPTION: &str = "Run the project's toolchain for this session: build, test, vet \
or run the code, and get the exit code, the elapsed time and bounded stdout and stderr back. \
It needs a session that declared can_execute. argv is the command as separate words, run \
directly with no shell, in a workspace materialized from the session's current graph head, \
including every change the session already committed. Only toolchain entry points run: for Go \
go build, test, vet, run, list, version, env (read-only), mod init and mod tidy; for Node npm \
test, npm run <script>, npm install, npm ci and node <entry>; for Python python -m pytest, \
unittest or a project module, and pytest; for Rust cargo build, test, run and check; and \
whatever the repository's [execution.agent] allow list in .kin/config.toml adds. A Go target \
is the repository's own package: go run . or go run ./cmd/app for its main package, and ./... \
or its module's import paths for go build, test and vet. Standard-library and toolchain paths \
such as cmd/gofmt, pkg@version and other modules are refused. Shells, command runners, inline \
code and file-dumping utilities are refused before anything runs. When \
the command succeeds, the manifests and lockfiles it wrote, such as go.mod and go.sum, are \
recorded as a change by this session. Source it wrote is refused and reported, because code \
changes through entity operations, and build outputs are never kept.";

/// The registered definition.
pub fn tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: TOOL_NAME.into(),
        description: DESCRIPTION.into(),
        annotations: ToolAnnotations {
            title: "Run the project's toolchain".into(),
            read_only_hint: false,
            // It records the manifests a toolchain rewrote over the ones the
            // repository held.
            destructive_hint: true,
            idempotent_hint: false,
            // A toolchain may reach a package registry.
            open_world_hint: true,
        },
        input_schema: json!({
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session_id kin_session_start returned. The session must declare can_execute; can_write and can_commit let it keep the manifests the command writes."
                },
                "argv": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": MAX_ARGV,
                    "description": "The command as separate words, run with no shell, such as [\"go\",\"test\",\"./...\"]."
                },
                "timeout_secs": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TIMEOUT_SECS,
                    "default": DEFAULT_TIMEOUT_SECS,
                    "description": "Seconds before the command is stopped."
                },
                "max_output_bytes": {
                    "type": "integer",
                    "minimum": MIN_OUTPUT_BYTES,
                    "maximum": MAX_OUTPUT_BYTES,
                    "default": DEFAULT_OUTPUT_BYTES,
                    "description": "The most bytes of stdout, and of stderr, returned. The middle of a longer stream is cut, and the answer says how much."
                },
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Plain application variables for the command, such as {\"TASKS_FILE\":\"tasks.json\"}, passed exactly as given and never expanded. A variable that changes how a program is found, loaded, built or fetched, such as PATH, LD_*, DYLD_*, GOFLAGS, GOPROXY, NODE_OPTIONS, PYTHONPATH or a proxy, is refused."
                },
                "summary": {
                    "type": "string",
                    "description": "The message recorded with the manifests and lockfiles the command writes. Defaults to one naming the command."
                }
            },
            "required": ["session_id", "argv"],
            "additionalProperties": false
        }),
    }
}

/// One call, as the launcher runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub session_id: String,
    pub argv: Vec<String>,
    /// Application variables set for the command, sorted by name, each
    /// already checked by [`refused_environment`].
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub summary: Option<String>,
}

/// Environment variables an agent may not set, by exact name: each changes
/// how a program is found, loaded, built or fetched, or who the command runs
/// as to Kin.
const DENIED_ENV_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "SHELL",
    "IFS",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "GOFLAGS",
    "GO111MODULE",
    "GOTOOLCHAIN",
    "GOPROXY",
    "GONOPROXY",
    "GOPRIVATE",
    "GOSUMDB",
    "GONOSUMDB",
    "GOINSECURE",
    "GOENV",
    "GOROOT",
    "GOPATH",
    "GOBIN",
    "GOCACHE",
    "GOMODCACHE",
    "GOTMPDIR",
    "GOWORK",
    "GOVCS",
    "GOAUTH",
    "GOEXPERIMENT",
    "GODEBUG",
    "GOFIPS140",
    "GOTELEMETRY",
    "GOTELEMETRYDIR",
    "GCCGO",
    "CC",
    "CXX",
    "AR",
    "FC",
    "PKG_CONFIG",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONINSPECT",
    "PYTHONEXECUTABLE",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
];

/// Prefixes of environment variables an agent may not set, compared without
/// regard to case: loader and linker variables, cgo and cargo settings, npm
/// configuration, git and ssh, rustup, and Kin's own.
const DENIED_ENV_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "CGO_",
    "CARGO_",
    "RUSTUP_",
    "NPM_CONFIG_",
    "GIT_",
    "SSH_",
    "KIN_",
];

/// Why an agent may not set `name`, or `None` when it is a plain application
/// variable.
pub fn refused_environment(name: &str) -> Option<String> {
    let valid = name
        .chars()
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric());
    if !valid {
        return Some(format!(
            "{name:?} is not an environment variable name: letters, digits and underscores, not starting with a digit."
        ));
    }
    let upper = name.to_ascii_uppercase();
    let denied = DENIED_ENV_NAMES.contains(&upper.as_str())
        || DENIED_ENV_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        || upper.ends_with("_PROXY");
    denied.then(|| {
        format!(
            "{name} changes how a program is found, loaded, built or fetched, so exec does not let a call set it. Pass plain application variables only, such as TASKS_FILE."
        )
    })
}

/// Read one call's arguments, or say what is wrong with them.
pub fn parse_request(arguments: &HashMap<String, Value>) -> Result<ExecRequest, String> {
    let mut extra: Vec<&String> = arguments
        .keys()
        .filter(|key| {
            !matches!(
                key.as_str(),
                "session_id" | "argv" | "env" | "timeout_secs" | "max_output_bytes" | "summary"
            )
        })
        .collect();
    extra.sort();
    if let Some(name) = extra.first() {
        return Err(format!("{TOOL_NAME} does not take {name}."));
    }
    let session_id = match arguments.get("session_id") {
        Some(Value::String(id)) if !id.trim().is_empty() => id.trim().to_string(),
        _ => {
            return Err(format!(
                "{TOOL_NAME} needs session_id, the id kin_session_start returned for a session \
                 that declared can_execute."
            ))
        }
    };
    let argv =
        match arguments.get("argv") {
            Some(Value::Array(words)) => words
                .iter()
                .map(|word| word.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| "argv must be an array of strings, one per word.".to_string())?,
            Some(Value::String(_)) => return Err(
                "argv must be an array of words, not one string: Kin runs no shell to split it, \
                 so send [\"go\",\"test\",\"./...\"] rather than \"go test ./...\"."
                    .to_string(),
            ),
            _ => {
                return Err(format!(
                    "{TOOL_NAME} needs argv, the command as an array of words."
                ))
            }
        };
    if argv.is_empty() || argv[0].trim().is_empty() {
        return Err("argv needs at least the program to run.".to_string());
    }
    if argv.len() as u64 > MAX_ARGV {
        return Err(format!("argv takes at most {MAX_ARGV} words."));
    }
    if argv.iter().any(|word| word.contains('\0')) {
        return Err("argv words may not contain a NUL byte.".to_string());
    }
    let timeout_secs = bounded_integer(
        arguments,
        "timeout_secs",
        DEFAULT_TIMEOUT_SECS,
        1,
        MAX_TIMEOUT_SECS,
    )?;
    let max_output_bytes = bounded_integer(
        arguments,
        "max_output_bytes",
        DEFAULT_OUTPUT_BYTES,
        MIN_OUTPUT_BYTES,
        MAX_OUTPUT_BYTES,
    )?;
    let env = match arguments.get("env") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(variables)) => {
            let mut env = Vec::with_capacity(variables.len());
            for (name, value) in variables {
                let Some(value) = value.as_str() else {
                    return Err(format!(
                        "env values are plain strings; {name} came as {value}."
                    ));
                };
                if value.contains('\0') {
                    return Err(format!("env value {name} may not contain a NUL byte."));
                }
                env.push((name.clone(), value.to_string()));
            }
            env.sort();
            env
        }
        Some(_) => return Err("env must be an object of names to string values.".to_string()),
    };
    let summary = match arguments.get("summary") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if text.trim().is_empty() => None,
        Some(Value::String(text)) => Some(text.trim().to_string()),
        Some(_) => return Err("summary must be a string.".to_string()),
    };
    Ok(ExecRequest {
        session_id,
        argv,
        env,
        timeout: Duration::from_secs(timeout_secs),
        max_output_bytes: max_output_bytes as usize,
        summary,
    })
}

fn bounded_integer(
    arguments: &HashMap<String, Value>,
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, String> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => match value.as_u64() {
            Some(number) if (minimum..=maximum).contains(&number) => Ok(number),
            _ => Err(format!(
                "{name} must be an integer from {minimum} to {maximum}."
            )),
        },
    }
}

/// A language whose toolchain entry points `kin_session_exec` runs by
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Go,
    Node,
    Python,
    Rust,
}

impl Language {
    pub const ALL: [Language; 4] = [Self::Go, Self::Node, Self::Python, Self::Rust];

    pub fn name(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Node => "node",
            Self::Python => "python",
            Self::Rust => "rust",
        }
    }

    /// The language a configured name means, spelled any common way.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "go" | "golang" => Some(Self::Go),
            "node" | "nodejs" | "javascript" | "js" | "typescript" | "ts" | "npm" => {
                Some(Self::Node)
            }
            "python" | "py" | "python3" => Some(Self::Python),
            "rust" | "rs" | "cargo" => Some(Self::Rust),
            _ => None,
        }
    }

    /// This language's default entry points, as a reader writes them.
    pub fn entry_points(self) -> &'static [&'static str] {
        match self {
            Self::Go => &[
                "go build",
                "go test",
                "go vet",
                "go run",
                "go list",
                "go version",
                "go env (read-only)",
                "go mod init",
                "go mod tidy",
            ],
            Self::Node => &[
                "npm test",
                "npm run <script>",
                "npm install",
                "npm ci",
                "node <entry.js>",
            ],
            Self::Python => &[
                "python -m pytest",
                "python -m unittest",
                "python -m <project module>",
                "pytest",
            ],
            Self::Rust => &["cargo build", "cargo test", "cargo run", "cargo check"],
        }
    }

    /// An example argv for this language, for a refusal to name.
    pub fn example_argv(self) -> &'static [&'static str] {
        match self {
            Self::Go => &["go", "test", "./..."],
            Self::Node => &["npm", "test"],
            Self::Python => &["python3", "-m", "pytest"],
            Self::Rust => &["cargo", "test"],
        }
    }
}

/// Why a command was refused before it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    /// A shell, which would evaluate a script.
    Shell,
    /// A program whose job is to run another program.
    CommandRunner,
    /// An interpreter given code inline or on stdin.
    InlineCode,
    /// A utility that reads, copies or rewrites files directly.
    FileDump,
    /// A path that reaches outside the session workspace.
    PathOutsideWorkspace,
    /// A toolchain flag that runs another program or reaches outside the
    /// workspace.
    RefusedFlag,
    /// An environment variable that changes how a program is found, loaded,
    /// built or fetched.
    RefusedEnvironment,
    /// A Go target that is not the repository's own package: the standard
    /// library, the toolchain's commands, a `pkg@version` or another module.
    PackageOutsideRepository,
    /// Not one of this project's toolchain entry points.
    NotAllowed,
}

impl RefusalKind {
    /// Whether the repository's configuration can allow this. Only a command
    /// that is merely not on the allow list can be; the rest are refused
    /// whatever the configuration says.
    pub fn configurable(self) -> bool {
        matches!(self, Self::NotAllowed)
    }
}

/// A command refused before anything ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRefusal {
    pub kind: RefusalKind,
    pub reason: String,
}

impl CommandRefusal {
    fn new(kind: RefusalKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            reason: reason.into(),
        }
    }
}

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "ash",
    "busybox",
    "cmd",
    "powershell",
    "pwsh",
    "nu",
    "xonsh",
    "elvish",
    "rc",
];

const COMMAND_RUNNERS: &[&str] = &[
    "env",
    "xargs",
    "nohup",
    "exec",
    "eval",
    "time",
    "timeout",
    "nice",
    "ionice",
    "sudo",
    "doas",
    "su",
    "runuser",
    "chroot",
    "setsid",
    "script",
    "expect",
    "watch",
    "parallel",
    "nsenter",
    "unshare",
    "ssh",
    "strace",
    "ltrace",
    "gdb",
    "lldb",
    "dtrace",
    "npx",
    "pnpx",
    "bunx",
    "osascript",
    "open",
    "xdg-open",
    "start",
];

const FILE_UTILITIES: &[&str] = &[
    "cat",
    "head",
    "tail",
    "sed",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "less",
    "more",
    "most",
    "xxd",
    "od",
    "hexdump",
    "hd",
    "strings",
    "cp",
    "mv",
    "tee",
    "dd",
    "nl",
    "tac",
    "rev",
    "base64",
    "base32",
    "uuencode",
    "split",
    "csplit",
    "fold",
    "fmt",
    "pr",
    "cut",
    "paste",
    "sort",
    "uniq",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ack",
    "find",
    "ls",
    "tree",
    "file",
    "diff",
    "cmp",
    "comm",
    "jq",
    "yq",
    "vi",
    "vim",
    "nvim",
    "nano",
    "emacs",
    "ed",
    "ex",
    "view",
    "bat",
    "ln",
    "install",
    "rsync",
    "scp",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gunzip",
    "zcat",
    "bzip2",
    "xz",
    "zstd",
    "curl",
    "wget",
    "nc",
    "netcat",
    "pbcopy",
    "pbpaste",
    "truncate",
    "shred",
    "rm",
    "rmdir",
    "mkdir",
    "touch",
    "chmod",
    "chown",
    "stat",
    "du",
    "wc",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "shasum",
    "cksum",
    "iconv",
    "look",
    "patch",
    "git",
];

/// Interpreters and the flags that hand them code inline.
const INLINE_CODE_FLAGS: &[(&str, &[&str])] = &[
    (
        "node",
        &[
            "-e",
            "--eval",
            "-p",
            "--print",
            "-pe",
            "-i",
            "--interactive",
        ],
    ),
    (
        "nodejs",
        &[
            "-e",
            "--eval",
            "-p",
            "--print",
            "-pe",
            "-i",
            "--interactive",
        ],
    ),
    ("bun", &["-e", "--eval", "-p", "--print"]),
    ("deno", &["eval", "repl"]),
    ("perl", &["-e", "-E"]),
    ("ruby", &["-e"]),
    ("php", &["-r", "-a"]),
    ("lua", &["-e"]),
    ("luajit", &["-e"]),
    ("rscript", &["-e"]),
    ("tclsh", &[]),
    ("irb", &[]),
];

/// Python standard-library modules that print or serve a file's bytes, which
/// `python -m` refuses even in a project that shadows one of their names.
const PYTHON_FILE_MODULES: &[&str] = &[
    "base64",
    "json.tool",
    "tokenize",
    "zipfile",
    "tarfile",
    "gzip",
    "bz2",
    "lzma",
    "http.server",
    "pydoc",
    "uu",
    "quopri",
    "pickletools",
    "dis",
    "ast",
    "code",
    "pdb",
    "trace",
    "runpy",
    "filecmp",
    "difflib",
    "shutil",
    "idlelib",
    "webbrowser",
    "pip",
];

/// A program's name as the lists above read it: its last path component,
/// lower-cased, with a Windows `.exe` dropped.
fn program_key(program: &str) -> String {
    let leaf = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    leaf.strip_suffix(".exe").unwrap_or(&leaf).to_string()
}

/// Whether `program` names a Python interpreter: `python`, `python3`,
/// `python3.12`, `pypy3`.
fn is_python(program: &str) -> bool {
    let key = program_key(program);
    ["python", "pypy"].iter().any(|stem| {
        key.strip_prefix(stem)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

/// Whether one word is, or carries after `=`, a path outside the workspace:
/// absolute, home-relative, or climbing out through `..`.
fn escapes_workspace(word: &str) -> bool {
    let value = match word.split_once('=') {
        Some((flag, value)) if flag.starts_with('-') => value,
        _ => word,
    };
    let bytes = value.as_bytes();
    let windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    value.starts_with('/')
        || value.starts_with('\\')
        || value.starts_with('~')
        || windows_drive
        || value.split(['/', '\\']).any(|component| component == "..")
}

/// Refuse what no configuration may allow, before anything runs: shells,
/// command runners, inline code, file utilities and paths that leave the
/// workspace.
pub fn refuse_before_running(argv: &[String]) -> Option<CommandRefusal> {
    let program = argv.first()?;
    let key = program_key(program);
    if SHELLS.contains(&key.as_str()) {
        return Some(CommandRefusal::new(
            RefusalKind::Shell,
            format!(
                "{program} is a shell, and exec runs no shell: a shell script reads and writes \
                 whole files, which Kin does through entity operations."
            ),
        ));
    }
    if COMMAND_RUNNERS.contains(&key.as_str()) {
        return Some(CommandRefusal::new(
            RefusalKind::CommandRunner,
            format!(
                "{program} runs another program, so it would reach past what exec allows. Name the \
                 toolchain command itself."
            ),
        ));
    }
    if FILE_UTILITIES.contains(&key.as_str()) {
        return Some(CommandRefusal::new(
            RefusalKind::FileDump,
            format!(
                "{program} reads, copies or rewrites files directly, which exec does not do. \
                 Read code with get_entity_source, one entity at a time, and change it with \
                 kin_mutate."
            ),
        ));
    }
    if is_python(program) {
        for word in argv.iter().skip(1) {
            if word == "-m" || !word.starts_with('-') {
                break;
            }
            let cluster = !word.starts_with("--") && word.len() > 1;
            if word == "-" || (cluster && word[1..].contains(['c', 'i'])) {
                return Some(CommandRefusal::new(
                    RefusalKind::InlineCode,
                    format!(
                        "{program} {word} runs code given inline or on stdin. Put the code in an \
                         entity and run the module with python -m."
                    ),
                ));
            }
        }
        if argv.len() == 1 {
            return Some(CommandRefusal::new(
                RefusalKind::InlineCode,
                format!("{program} with no module starts an interactive interpreter."),
            ));
        }
    }
    if let Some((_, flags)) = INLINE_CODE_FLAGS.iter().find(|(name, _)| *name == key) {
        let inline = argv.iter().skip(1).find(|word| {
            flags.iter().any(|flag| {
                word.as_str() == *flag
                    || (flag.starts_with("--") && word.starts_with(&format!("{flag}=")))
            })
        });
        if flags.is_empty() || argv.len() == 1 || inline.is_some() {
            return Some(CommandRefusal::new(
                RefusalKind::InlineCode,
                format!(
                    "{program}{} runs code given inline or interactively. Put the code in an entity \
                     and run it from there.",
                    inline.map(|word| format!(" {word}")).unwrap_or_default()
                ),
            ));
        }
    }
    if let Some(word) = argv.iter().skip(1).find(|word| escapes_workspace(word)) {
        return Some(CommandRefusal::new(
            RefusalKind::PathOutsideWorkspace,
            format!(
                "{word:?} names a path outside the session workspace. Every path exec takes is \
                 relative to the workspace root and stays inside it."
            ),
        ));
    }
    None
}

/// What a command is checked against once the project is known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandPolicy {
    /// The languages whose default entry points apply.
    pub languages: Vec<Language>,
    /// Extra command prefixes the repository allows, as words.
    pub extra: Vec<Vec<String>>,
    /// The project's own top-level Python modules, which `python -m` may run.
    pub python_modules: Vec<String>,
    /// The repository's own Go modules, which a Go target must be in.
    pub go: GoModules,
}

impl CommandPolicy {
    /// Every entry point this policy allows, as a reader writes them.
    pub fn allowed(&self) -> Vec<String> {
        let mut allowed: Vec<String> = self
            .languages
            .iter()
            .flat_map(|language| {
                language
                    .entry_points()
                    .iter()
                    .map(|entry| entry.to_string())
            })
            .collect();
        allowed.extend(self.extra.iter().map(|words| words.join(" ")));
        allowed
    }

    /// One command this policy allows, for a refusal to name.
    pub fn example_argv(&self) -> Vec<String> {
        if let Some(language) = self.languages.first() {
            return language
                .example_argv()
                .iter()
                .map(|word| word.to_string())
                .collect();
        }
        if let Some(words) = self.extra.first() {
            return words.clone();
        }
        Language::Go
            .example_argv()
            .iter()
            .map(|word| word.to_string())
            .collect()
    }
}

/// Whether `argv` may run under `policy`, checked after
/// [`refuse_before_running`].
///
/// A command runs when it is one of the project's languages' entry points or
/// begins with a prefix the repository configured. Configuration adds
/// commands; it never lifts a language's own refusals. A flag that hands a Go
/// build to another program, an npm option that swaps its script shell, a
/// cargo `--config` or a Python module that prints files is refused whatever
/// prefix the repository allows.
pub fn admit(argv: &[String], policy: &CommandPolicy) -> Result<(), CommandRefusal> {
    if let Some(refusal) = refuse_before_running(argv) {
        return Err(refusal);
    }
    let program = argv[0].as_str();
    let configured = policy
        .extra
        .iter()
        .any(|prefix| !prefix.is_empty() && argv.starts_with(prefix));
    let language = language_of(program);
    let checked = match language {
        Some(Language::Go) => check_go(argv, configured, Some(&policy.go)),
        Some(Language::Node) => check_node(argv, configured),
        Some(Language::Python) => check_python(argv, &policy.python_modules, configured),
        Some(Language::Rust) => check_rust(argv, configured),
        None if configured => Ok(()),
        None => Err(CommandRefusal::new(RefusalKind::NotAllowed, "")),
    };
    if let Err(refusal) = checked {
        return Err(match refusal.kind {
            RefusalKind::NotAllowed => not_allowed(argv, policy, &refusal.reason),
            _ => refusal,
        });
    }
    if configured {
        return Ok(());
    }
    if program.contains(['/', '\\']) {
        return Err(not_allowed(
            argv,
            policy,
            "name the toolchain program by its bare name, which is looked up on PATH",
        ));
    }
    match language {
        Some(language) if policy.languages.contains(&language) => Ok(()),
        _ => Err(not_allowed(argv, policy, "")),
    }
}

/// Refuse a toolchain command whose flags no configuration may allow: a Go
/// flag that hands the build to another program, an npm option that swaps its
/// script shell, a cargo `--config`, a node option before the entry point, or
/// a Python module that prints files. Needs no project, so the server refuses
/// these before it asks the launcher for anything.
pub fn refuse_toolchain_flags(argv: &[String]) -> Option<CommandRefusal> {
    let checked = match language_of(argv.first()?) {
        Some(Language::Go) => check_go(argv, true, None),
        Some(Language::Node) => check_node(argv, true),
        Some(Language::Python) => check_python(argv, &[], true),
        Some(Language::Rust) => check_rust(argv, true),
        None => Ok(()),
    };
    checked
        .err()
        .filter(|refusal| refusal.kind != RefusalKind::NotAllowed)
}

/// The language whose toolchain `program` is.
pub fn language_of(program: &str) -> Option<Language> {
    match program_key(program).as_str() {
        "go" => Some(Language::Go),
        "npm" | "node" | "nodejs" => Some(Language::Node),
        "cargo" => Some(Language::Rust),
        "pytest" => Some(Language::Python),
        _ if is_python(program) => Some(Language::Python),
        _ => None,
    }
}

fn not_allowed(argv: &[String], policy: &CommandPolicy, detail: &str) -> CommandRefusal {
    let languages = if policy.languages.is_empty() {
        "no language Kin runs by default".to_string()
    } else {
        policy
            .languages
            .iter()
            .map(|language| language.name())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!(" ({detail})")
    };
    CommandRefusal::new(
        RefusalKind::NotAllowed,
        format!(
            "`{}` is not one of this project's toolchain entry points{detail}. The project is \
             {languages}, so exec runs: {}. The repository can allow another command by adding \
             its first words to allow under [execution.agent] in .kin/config.toml.",
            argv.join(" "),
            policy.allowed().join(", ")
        ),
    )
}

fn refused_flag(word: &str, why: &str) -> CommandRefusal {
    CommandRefusal::new(RefusalKind::RefusedFlag, format!("{word} {why}"))
}

/// A flag word's name without its dashes, and its inline `=` value.
fn flag_parts(word: &str) -> (&str, Option<&str>) {
    let body = word.trim_start_matches('-');
    match body.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (body, None),
    }
}

/// Go flags that hand the build to another program, read another module
/// file, or reach outside what exec runs. Refused in every position and
/// whatever the repository configures.
const GO_DENIED_FLAGS: &[&str] = &[
    "exec",
    "toolexec",
    "vettool",
    "overlay",
    "modfile",
    "asmflags",
    "gccgoflags",
    "compiler",
    "pkgdir",
    "linkshared",
    "debug-actiongraph",
    "debug-runtime-trace",
    "debug-trace",
];

/// Words that, inside a `-ldflags` or `-gcflags` value, name an external
/// linker, archiver or configuration file, each a way to run or read what
/// exec does not allow.
const GO_DENIED_TOOL_FLAG_WORDS: &[&str] = &[
    "extld",
    "extar",
    "importcfg",
    "embedcfg",
    "fuse-ld",
    "toolexec",
];

/// Build flags every admitted Go subcommand takes, that take a value.
const GO_BUILD_VALUE_FLAGS: &[&str] = &[
    "C",
    "o",
    "p",
    "buildmode",
    "covermode",
    "coverpkg",
    "gcflags",
    "installsuffix",
    "ldflags",
    "mod",
    "pgo",
    "tags",
];

/// Build flags every admitted Go subcommand takes, that stand alone or take
/// an inline `=` value.
const GO_BUILD_BOOL_FLAGS: &[&str] = &[
    "a",
    "n",
    "race",
    "msan",
    "asan",
    "cover",
    "v",
    "work",
    "x",
    "modcacherw",
    "trimpath",
    "json",
    "buildvcs",
];

const GO_TEST_VALUE_FLAGS: &[&str] = &[
    "bench",
    "benchtime",
    "blockprofile",
    "blockprofilerate",
    "count",
    "coverprofile",
    "cpu",
    "cpuprofile",
    "fuzz",
    "fuzzminimizetime",
    "fuzztime",
    "list",
    "memprofile",
    "memprofilerate",
    "mutexprofile",
    "mutexprofilefraction",
    "outputdir",
    "parallel",
    "run",
    "shuffle",
    "skip",
    "timeout",
    "trace",
    "vet",
];

const GO_TEST_BOOL_FLAGS: &[&str] = &["benchmem", "c", "failfast", "fullpath", "short"];

const GO_LIST_VALUE_FLAGS: &[&str] = &["f", "reuse"];

const GO_LIST_BOOL_FLAGS: &[&str] = &[
    "m",
    "u",
    "versions",
    "deps",
    "test",
    "e",
    "find",
    "export",
    "compiled",
    "retracted",
];

const GO_MOD_TIDY_VALUE_FLAGS: &[&str] = &["go", "compat"];

const GO_MOD_TIDY_BOOL_FLAGS: &[&str] = &["v", "e", "x", "diff"];

/// `go env` flags that write the user's Go environment file. It lives outside
/// the workspace, and a `GOFLAGS` written there reaches every later go
/// command, so these are refused whatever the repository configures.
const GO_ENV_WRITE_FLAGS: &[&str] = &["w", "u"];

/// `go env` as exec runs it, only to read: no words, `-json`, or Go
/// environment variable names, alone or after `-json`. Any other word,
/// `--` and every other flag included, is refused before anything runs,
/// whatever the repository configures.
fn check_go_env(words: &[String]) -> Result<(), CommandRefusal> {
    // Checked first and in every position, so a write is named as one.
    if let Some(word) = words
        .iter()
        .find(|word| word.starts_with('-') && GO_ENV_WRITE_FLAGS.contains(&flag_parts(word).0))
    {
        return Err(refused_flag(
            word,
            "writes the user's Go environment file, outside the session workspace, where it \
             would change every later go command. exec runs go env only to read: name the \
             variables, after -json for JSON.",
        ));
    }
    let names = match words {
        [first, rest @ ..] if first == "-json" => rest,
        _ => words,
    };
    match names.iter().find(|word| !is_go_env_name(word)) {
        None => Ok(()),
        Some(word) => Err(refused_flag(
            word,
            "is not something exec passes to go env, which runs only to read: name variables \
             such as GOPATH, after -json for JSON.",
        )),
    }
}

/// Whether `word` reads as a Go environment variable name: an upper-case
/// letter, then upper-case letters, digits and underscores.
fn is_go_env_name(word: &str) -> bool {
    let mut chars = word.chars();
    chars.next().is_some_and(|first| first.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// What the words of a Go subcommand that are not flags mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoPositional {
    /// Not packages exec reads, as for `go list` and `go mod tidy`.
    Unread,
    /// `go run`: the first word that is not a flag is the package, or the
    /// `.go` files that begin there, and every word after it is the
    /// program's own.
    Target,
    /// `go build`, `go test` and `go vet`: every such word is a package,
    /// before `-args` for `go test`.
    Packages,
}

/// How one Go subcommand's words are read.
struct GoGrammar<'a> {
    value: &'a [&'a [&'a str]],
    boolean: &'a [&'a [&'a str]],
    positional: GoPositional,
    /// `go test`: `-args` hands every word after it to the test binary.
    args_marker: bool,
}

/// The packages a Go build, run, test or vet command names, as its grammar
/// reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoTargets {
    /// Whether the command is `go run`, whose target must be a main package.
    pub run: bool,
    /// The directory `-C` moves the command to, relative to the workspace.
    pub dir: Option<String>,
    /// The package paths, patterns or `.go` files, in order. Empty means the
    /// directory the command runs in.
    pub packages: Vec<String>,
}

/// `go run`'s target: the `.go` files that begin at the first word, or that
/// one word, with every word after it the program's own.
fn run_target(rest: &[String]) -> Vec<String> {
    match rest.first() {
        Some(first) if first.ends_with(".go") => rest
            .iter()
            .take_while(|word| word.ends_with(".go"))
            .cloned()
            .collect(),
        Some(first) => vec![first.clone()],
        None => Vec::new(),
    }
}

/// Read every word of a Go subcommand against its grammar: a denied flag or
/// one this grammar does not know is refused, a value-taking flag consumes
/// its value, and a linker or compiler flag value that names an external
/// tool is refused. Nothing is skipped because it looked like a value. The
/// words that are not flags come back as the command's packages, `--` and
/// all: `go run -- cmd/gofmt` names `cmd/gofmt` as its target.
fn check_go_words(words: &[String], grammar: &GoGrammar<'_>) -> Result<GoTargets, CommandRefusal> {
    const WHY: &str =
        "hands the build to another program or reaches outside the project, which exec does not \
         allow.";
    let mut targets = GoTargets {
        run: grammar.positional == GoPositional::Target,
        ..GoTargets::default()
    };
    let mut index = 0;
    while index < words.len() {
        let word = words[index].as_str();
        if word == "--" {
            // `go test` hands `--` and every word after it to the test
            // binary, as it does `-args`. For every other subcommand each word
            // after it is positional.
            let rest = &words[index + 1..];
            match grammar.positional {
                GoPositional::Unread => {}
                GoPositional::Target => targets.packages = run_target(rest),
                GoPositional::Packages if grammar.args_marker => {}
                GoPositional::Packages => targets.packages.extend(rest.iter().cloned()),
            }
            return Ok(targets);
        }
        if !word.starts_with('-') || word == "-" {
            match grammar.positional {
                GoPositional::Unread => {}
                GoPositional::Target => {
                    targets.packages = run_target(&words[index..]);
                    return Ok(targets);
                }
                GoPositional::Packages => targets.packages.push(word.to_string()),
            }
            index += 1;
            continue;
        }
        if word.starts_with("---") {
            return Err(refused_flag(
                word,
                "is not a flag exec can read, so it is refused.",
            ));
        }
        let (mut name, inline) = flag_parts(word);
        if grammar.args_marker && name == "args" {
            return Ok(targets);
        }
        if grammar.args_marker {
            name = name.strip_prefix("test.").unwrap_or(name);
        }
        if GO_DENIED_FLAGS.contains(&name) {
            return Err(refused_flag(word, WHY));
        }
        if grammar.value.iter().any(|flags| flags.contains(&name)) {
            let value = match inline {
                Some(value) => value,
                None => match words.get(index + 1) {
                    Some(value) => {
                        index += 1;
                        value.as_str()
                    }
                    None => {
                        return Err(refused_flag(
                            word,
                            "needs a value, and a flag exec cannot read is refused.",
                        ))
                    }
                },
            };
            if matches!(name, "ldflags" | "gcflags")
                && GO_DENIED_TOOL_FLAG_WORDS
                    .iter()
                    .any(|denied| value.contains(denied))
            {
                return Err(refused_flag(
                    &format!("{word} {value}"),
                    "names an external linker, archiver or configuration file, which exec does \
                     not allow.",
                ));
            }
            if name == "C" {
                targets.dir = Some(value.to_string());
            }
            index += 1;
            continue;
        }
        if grammar.boolean.iter().any(|flags| flags.contains(&name)) {
            index += 1;
            continue;
        }
        return Err(refused_flag(
            word,
            "is not a flag exec knows for this go command, and a flag exec cannot read is \
             refused. Pass a test binary's own flags after -args.",
        ));
    }
    Ok(targets)
}

/// The grammar of a Go subcommand that takes packages: build, vet, run and
/// test.
fn package_grammar(subcommand: &str) -> Option<GoGrammar<'static>> {
    let (value, boolean, positional, args_marker): (
        &'static [&'static [&'static str]],
        &'static [&'static [&'static str]],
        GoPositional,
        bool,
    ) = match subcommand {
        "build" | "vet" => (
            &[GO_BUILD_VALUE_FLAGS],
            &[GO_BUILD_BOOL_FLAGS],
            GoPositional::Packages,
            false,
        ),
        "run" => (
            &[GO_BUILD_VALUE_FLAGS],
            &[GO_BUILD_BOOL_FLAGS],
            GoPositional::Target,
            false,
        ),
        "test" => (
            &[GO_BUILD_VALUE_FLAGS, GO_TEST_VALUE_FLAGS],
            &[GO_BUILD_BOOL_FLAGS, GO_TEST_BOOL_FLAGS],
            GoPositional::Packages,
            true,
        ),
        _ => return None,
    };
    Some(GoGrammar {
        value,
        boolean,
        positional,
        args_marker,
    })
}

/// Split Go's global `-C dir`, which it takes only before the subcommand,
/// from the words after it.
fn global_dir(words: &[String]) -> (Option<&str>, &[String]) {
    match words.first().map(String::as_str) {
        Some("-C" | "--C") if words.len() > 1 => (Some(words[1].as_str()), &words[2..]),
        Some(word) => match word
            .strip_prefix("-C=")
            .or_else(|| word.strip_prefix("--C="))
        {
            Some(dir) => (Some(dir), &words[1..]),
            None => (None, words),
        },
        None => (None, words),
    }
}

/// A package subcommand's words read against its grammar, with a global
/// `-C` joined to the one the subcommand takes.
fn read_go_targets(
    global: Option<&str>,
    words: &[String],
    grammar: &GoGrammar<'_>,
) -> Result<GoTargets, CommandRefusal> {
    let mut targets = check_go_words(words, grammar)?;
    targets.dir = match (global, targets.dir.take()) {
        (Some(outer), Some(inner)) => Some(format!("{outer}/{inner}")),
        (outer, inner) => inner.or_else(|| outer.map(str::to_string)),
    };
    Ok(targets)
}

/// The packages a `go build`, `go run`, `go test` or `go vet` command names,
/// or `None` for any other command or one whose flags exec refuses.
pub fn go_targets(argv: &[String]) -> Option<GoTargets> {
    if language_of(argv.first()?)? != Language::Go {
        return None;
    }
    let (global, words) = global_dir(&argv[1..]);
    let grammar = package_grammar(words.first()?)?;
    read_go_targets(global, &words[1..], &grammar).ok()
}

/// Check a Go command. `modules` is what the launcher read of the
/// repository's Go modules, and `None` when the server checks a command
/// before it asks the launcher for anything: every target that needs no
/// module to judge is judged then.
fn check_go(
    argv: &[String],
    configured: bool,
    modules: Option<&GoModules>,
) -> Result<(), CommandRefusal> {
    let build_value: &[&str] = GO_BUILD_VALUE_FLAGS;
    let build_bool: &[&str] = GO_BUILD_BOOL_FLAGS;
    // `go -C dir run ...` moves the command before it reads the subcommand,
    // so the subcommand is read after it and its targets relative to it.
    let (global, words) = global_dir(&argv[1..]);
    if let Some(grammar) = words.first().and_then(|word| package_grammar(word)) {
        // A configured prefix adds commands and never lifts this: a target
        // outside the repository is refused whatever allows `go` or `go run`.
        let targets = read_go_targets(global, &words[1..], &grammar)?;
        return check_go_targets(&targets, modules);
    }
    let (grammar, rest) = match words.first().map(String::as_str) {
        Some("list") => (
            GoGrammar {
                value: &[build_value, GO_LIST_VALUE_FLAGS],
                boolean: &[build_bool, GO_LIST_BOOL_FLAGS],
                positional: GoPositional::Unread,
                args_marker: false,
            },
            &words[1..],
        ),
        Some("version") => {
            // The toolchain's own version and nothing else: no flag, and no
            // binary or directory for it to read.
            return match &words[1..] {
                [] => Ok(()),
                [word, ..] => Err(refused_flag(
                    word,
                    "is not something exec passes to go version, which runs by itself to print \
                     the toolchain's version.",
                )),
            };
        }
        Some("env") => return check_go_env(&words[1..]),
        Some("mod") if words.get(1).map(String::as_str) == Some("tidy") => (
            GoGrammar {
                value: &[GO_MOD_TIDY_VALUE_FLAGS],
                boolean: &[GO_MOD_TIDY_BOOL_FLAGS],
                positional: GoPositional::Unread,
                args_marker: false,
            },
            &words[2..],
        ),
        Some("mod") if words.get(1).map(String::as_str) == Some("init") => {
            // One module path, and nothing that reads as a flag.
            return match &words[2..] {
                [] => Ok(()),
                [path] if !path.starts_with('-') => Ok(()),
                _ => Err(CommandRefusal::new(
                    RefusalKind::RefusedFlag,
                    "go mod init takes one module path and no flags.",
                )),
            };
        }
        _ => {
            // A subcommand only configuration allows. Its grammar is not one
            // exec knows, so every word is read for a denied flag.
            for word in words {
                if word.starts_with('-') && GO_DENIED_FLAGS.contains(&flag_parts(word).0) {
                    return Err(refused_flag(
                        word,
                        "hands the build to another program or reaches outside the project, \
                         which exec does not allow.",
                    ));
                }
            }
            return if configured {
                Ok(())
            } else {
                Err(CommandRefusal::new(RefusalKind::NotAllowed, ""))
            };
        }
    };
    check_go_words(rest, &grammar).map(|_| ())
}

/// The Go modules a repository's own packages live in, as the launcher read
/// them from the workspace's committed go.mod and go.work files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoModules {
    /// The repository's own modules: the go.mod at the workspace root, and
    /// each module its go.work uses inside the workspace.
    pub main: Vec<GoModule>,
    /// Module paths the build takes from elsewhere: every module those go.mod
    /// and go.work files require or replace. A package under one is never
    /// the repository's own, even when its path sits under a main module's.
    pub other: Vec<String>,
    /// Why no import path can be read as the repository's own, when none
    /// can: a go.work that uses a directory outside the workspace, say.
    pub unresolved: Option<String>,
}

/// One of the repository's own Go modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoModule {
    /// The module path its go.mod declares.
    pub path: String,
    /// Its directory relative to the workspace root, `.` for the root.
    pub dir: String,
}

impl GoModules {
    /// The main module that owns `pattern`, an import path or a pattern with
    /// `...`, or `None` when no main module does or another module in the
    /// build could supply a package it names.
    pub fn owner(&self, pattern: &str) -> Option<&GoModule> {
        let wildcard = pattern.find("...");
        let literal = wildcard.map_or(pattern, |at| &pattern[..at]);
        let under = |module: &str| match wildcard {
            None => {
                pattern == module
                    || pattern
                        .strip_prefix(module)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
            Some(_) => literal
                .strip_prefix(module)
                .is_some_and(|rest| rest.starts_with('/')),
        };
        let owner = self
            .main
            .iter()
            .filter(|module| under(&module.path))
            .max_by_key(|module| module.path.len())?;
        let shadowed = self.other.iter().any(|other| {
            (under(other) && other.len() >= owner.path.len())
                || (wildcard.is_some() && other.starts_with(literal))
        });
        (!shadowed).then_some(owner)
    }
}

/// Every `go` meta-pattern that names packages beyond the repository's own.
const GO_META_PATTERNS: &[&str] = &["std", "cmd", "all", "tool"];

/// Whether a Go package argument is a path rather than an import path: `.`,
/// `./x`, a `.go` file, or a path that leaves the workspace, which is
/// refused as one.
fn is_go_local_path(word: &str) -> bool {
    word == "."
        || word.starts_with("./")
        || word.starts_with(".\\")
        || word.ends_with(".go")
        || escapes_workspace(word)
}

/// The directory a `.go` file argument names, with any leading `./` dropped.
fn go_file_dir(word: &str) -> &str {
    let mut path = word;
    while let Some(rest) = path.strip_prefix("./") {
        path = rest;
    }
    path.rsplit_once('/').map_or(".", |(dir, _)| dir)
}

/// A refusal of a Go target that is not the repository's own code: `word`,
/// why, and what exec runs instead.
pub fn outside_repository(word: &str, why: &str) -> CommandRefusal {
    CommandRefusal::new(
        RefusalKind::PackageOutsideRepository,
        format!(
            "{word} {why} exec runs the repository's own Go packages only: go run . or go run \
             ./path/to/cmd for your main package, and ./... or ./path for go build, go test and \
             go vet. A program from outside the repository run over its files is not how a Kin \
             agent reads code: read it by entity with get_entity_source, the source command on \
             the routed tool."
        ),
    )
}

/// Refuse a Go build, run, test or vet target that is not the repository's
/// own: a standard-library or toolchain path, a meta-pattern, a
/// `pkg@version`, a path outside the workspace or under `vendor`, `.go` files
/// in more than one directory, or, once `modules` is known, an import path
/// no main module owns.
fn check_go_targets(
    targets: &GoTargets,
    modules: Option<&GoModules>,
) -> Result<(), CommandRefusal> {
    let mut file_dir: Option<&str> = None;
    for word in &targets.packages {
        check_go_target(word, targets, modules)?;
        if word.ends_with(".go") {
            let dir = go_file_dir(word);
            match file_dir {
                None => file_dir = Some(dir),
                Some(seen) if seen == dir => {}
                Some(_) => {
                    return Err(outside_repository(
                        word,
                        "is in another directory than the .go files before it, and the files of \
                         one main package share one directory.",
                    ))
                }
            }
        }
    }
    Ok(())
}

fn check_go_target(
    word: &str,
    targets: &GoTargets,
    modules: Option<&GoModules>,
) -> Result<(), CommandRefusal> {
    if word.starts_with('-') {
        return Err(outside_repository(
            word,
            "is not a package: every word after -- is read as one.",
        ));
    }
    if word.contains('@') {
        return Err(outside_repository(
            word,
            "names a module version to fetch and build, which is another project's code, not \
             this repository's.",
        ));
    }
    if is_go_local_path(word) {
        if escapes_workspace(word) {
            return Err(CommandRefusal::new(
                RefusalKind::PathOutsideWorkspace,
                format!(
                    "{word:?} names a path outside the session workspace. Every path exec takes \
                     is relative to the workspace root and stays inside it."
                ),
            ));
        }
        if word.split(['/', '\\']).any(|part| part == "vendor") {
            return Err(outside_repository(
                word,
                "is under a vendor directory, which holds other modules' packages.",
            ));
        }
        return Ok(());
    }
    if GO_META_PATTERNS.contains(&word) {
        return Err(outside_repository(
            word,
            "is a pattern over the standard library, the toolchain's commands or the build's \
             dependencies, not the repository's packages.",
        ));
    }
    let first = word.split('/').next().unwrap_or(word);
    if first.contains("...") || !first.contains('.') {
        return Err(outside_repository(
            word,
            "is in the standard library's namespace: Go reads an import path whose first element \
             has no dot as the standard library or the toolchain's own cmd tree, so exec never \
             reads it as the repository's. Name a package of the repository by its path, such as \
             ./cmd/app.",
        ));
    }
    if targets.dir.is_some() {
        return Err(outside_repository(
            word,
            "is an import path given with -C, which moves the command to a directory whose \
             module exec does not read. Name the package by its path relative to that directory, \
             such as ./cmd/app.",
        ));
    }
    let Some(modules) = modules else {
        // Only the repository's module path tells its own import paths from
        // another module's, and the launcher reads it before anything runs.
        return Ok(());
    };
    if let Some(why) = &modules.unresolved {
        return Err(outside_repository(word, why));
    }
    if modules.owner(word).is_some() {
        return Ok(());
    }
    let why = if modules.main.is_empty() {
        "is an import path, and the workspace has no go.mod, so no import path is the \
         repository's own. Create the module with go mod init first."
            .to_string()
    } else {
        let paths = modules
            .main
            .iter()
            .map(|module| module.path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "is not a package of the repository's own module ({paths}): another module's code, \
             or the standard library's."
        )
    };
    Err(outside_repository(word, &why))
}

/// Split GOFLAGS the way Go does (cmd/internal/quoted): fields apart on
/// spaces, tabs and newlines, and a field that opens with a single or double
/// quote runs to the next same quote, taken as written with no escapes.
/// `None` for an unterminated quote.
fn split_goflags(value: &str) -> Option<Vec<String>> {
    let is_space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
    let bytes = value.as_bytes();
    let mut fields = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        while at < bytes.len() && is_space(bytes[at]) {
            at += 1;
        }
        if at == bytes.len() {
            break;
        }
        let start = at;
        if matches!(bytes[at], b'"' | b'\'') {
            let quote = bytes[at];
            let end = bytes[at + 1..].iter().position(|byte| *byte == quote)? + at + 1;
            fields.push(value[at + 1..end].to_string());
            at = end + 1;
            continue;
        }
        while at < bytes.len() && !is_space(bytes[at]) {
            at += 1;
        }
        fields.push(value[start..at].to_string());
    }
    Some(fields)
}

/// Refuse a Go build, run, test or vet when the GOFLAGS it would run with,
/// which the Kin server's own environment or Go environment file sets rather
/// than the call, carries what exec refuses in argv. GOFLAGS is split the way
/// Go splits it, and each flag is read against the grammar argv is read
/// against, so a flag that swaps the go.mod, overlays files, moves the
/// command or hands the build to another program is refused however it is
/// quoted, as is a flag exec cannot read or a quote Go would not accept.
/// The refusal for a Go environment file exec cannot verify the way Go reads
/// it: larger than exec reads, or not a regular file once symbolic links are
/// followed. Its GOFLAGS could change which module or files a go command
/// builds, so an unverified file refuses rather than being skipped.
pub fn unverifiable_go_env_file(path: &str, why: &str) -> CommandRefusal {
    CommandRefusal::new(
        RefusalKind::RefusedEnvironment,
        format!(
            "The Go environment file {path} {why} Its GOFLAGS could change which module or files a \
             go command builds, so exec does not run go build, run, test or vet under it. The \
             operator can fix or remove it."
        ),
    )
}

pub fn refused_inherited_goflags(goflags: &str, source: &str) -> Option<CommandRefusal> {
    let refuse = |what: String| {
        Some(CommandRefusal::new(
            RefusalKind::RefusedEnvironment,
            format!(
                "GOFLAGS from {source} {what} It could change which module or files a go \
                 command builds, so exec does not run go build, run, test or vet under it. The \
                 operator can change it there."
            ),
        ))
    };
    let Some(fields) = split_goflags(goflags) else {
        return refuse("has a quote Go would not accept.".to_string());
    };
    let grammar = GoGrammar {
        value: &[
            GO_BUILD_VALUE_FLAGS,
            GO_TEST_VALUE_FLAGS,
            GO_LIST_VALUE_FLAGS,
        ],
        boolean: &[GO_BUILD_BOOL_FLAGS, GO_TEST_BOOL_FLAGS, GO_LIST_BOOL_FLAGS],
        positional: GoPositional::Unread,
        args_marker: false,
    };
    for field in &fields {
        if !field.starts_with('-') {
            return refuse(format!("carries {field:?}, which is not a flag."));
        }
        if flag_parts(field).0 == "C" {
            return refuse(format!("carries {field}, which moves the command."));
        }
        if let Err(refusal) = check_go_words(std::slice::from_ref(field), &grammar) {
            return refuse(format!("carries a flag exec refuses: {}", refusal.reason));
        }
    }
    None
}

const NPM_DENIED_FLAGS: &[&str] = &[
    "g",
    "global",
    "location",
    "prefix",
    "script-shell",
    "node-options",
    "userconfig",
    "globalconfig",
    "call",
    "c",
    "shell",
];

fn check_node(argv: &[String], configured: bool) -> Result<(), CommandRefusal> {
    let program = program_key(&argv[0]);
    if program == "npm" {
        for word in &argv[1..] {
            if word == "--" {
                break;
            }
            if word.starts_with('-') && NPM_DENIED_FLAGS.contains(&flag_parts(word).0) {
                return Err(refused_flag(
                    word,
                    "reaches outside the project or hands npm's scripts to another shell, which \
                     exec does not allow.",
                ));
            }
        }
        return match argv.get(1).map(String::as_str) {
            Some("test" | "t" | "install" | "i" | "ci") => Ok(()),
            Some("run" | "run-script") => match argv.get(2) {
                Some(script) if !script.starts_with('-') => Ok(()),
                _ => Err(CommandRefusal::new(
                    RefusalKind::NotAllowed,
                    "npm run needs the script's name",
                )),
            },
            _ if configured => Ok(()),
            _ => Err(CommandRefusal::new(RefusalKind::NotAllowed, "")),
        };
    }
    match argv.get(1) {
        Some(entry) if entry.starts_with('-') => Err(refused_flag(
            entry,
            "is a node option before the entry point, and exec runs a project's entry point with \
             no node options.",
        )),
        Some(entry)
            if [".js", ".mjs", ".cjs"]
                .iter()
                .any(|extension| entry.ends_with(extension)) =>
        {
            Ok(())
        }
        _ if configured => Ok(()),
        _ => Err(CommandRefusal::new(
            RefusalKind::NotAllowed,
            "node runs one of the project's .js, .mjs or .cjs entry points",
        )),
    }
}

fn check_python(
    argv: &[String],
    project_modules: &[String],
    configured: bool,
) -> Result<(), CommandRefusal> {
    if program_key(&argv[0]) == "pytest" {
        return Ok(());
    }
    // A module that prints, serves or copies files is refused wherever -m
    // appears, and whatever the repository configures.
    if let Some(module) = argv
        .windows(2)
        .find(|pair| pair[0] == "-m")
        .map(|pair| pair[1].as_str())
    {
        if PYTHON_FILE_MODULES.contains(&module) {
            return Err(CommandRefusal::new(
                RefusalKind::FileDump,
                format!(
                    "python -m {module} prints, serves or copies files, which exec does not \
                     allow."
                ),
            ));
        }
    }
    if configured {
        return Ok(());
    }
    if argv.get(1).map(String::as_str) != Some("-m") {
        return Err(CommandRefusal::new(
            RefusalKind::NotAllowed,
            "python runs a module with -m",
        ));
    }
    let Some(module) = argv.get(2) else {
        return Err(CommandRefusal::new(
            RefusalKind::NotAllowed,
            "python -m needs the module's name",
        ));
    };
    if matches!(module.as_str(), "pytest" | "unittest") {
        return Ok(());
    }
    let top = module.split('.').next().unwrap_or(module);
    if project_modules.iter().any(|name| name == top) {
        return Ok(());
    }
    Err(CommandRefusal::new(
        RefusalKind::NotAllowed,
        format!("{module} is not one of the project's own modules"),
    ))
}

fn check_rust(argv: &[String], configured: bool) -> Result<(), CommandRefusal> {
    let rest = match argv.get(1) {
        Some(toolchain) if toolchain.starts_with('+') => &argv[2..],
        _ => &argv[1..],
    };
    for word in rest {
        if word == "--" {
            break;
        }
        let (name, _) = flag_parts(word);
        if word.starts_with('-') && (name == "config" || word.starts_with("-Z")) {
            return Err(refused_flag(
                word,
                "changes how cargo runs its tools, which exec does not allow.",
            ));
        }
    }
    match rest.first().map(String::as_str) {
        Some("build" | "b" | "test" | "t" | "run" | "r" | "check" | "c") => Ok(()),
        _ if configured => Ok(()),
        _ => Err(CommandRefusal::new(RefusalKind::NotAllowed, "")),
    }
}

/// Bounded capture of one output stream: the first half of the bound and the
/// last half, with the count of what fell between them.
///
/// A build or test run's first error and its closing summary are the two ends
/// a reader needs, so the middle is what gives way.
#[derive(Debug, Clone)]
pub struct BoundedCapture {
    head_cap: usize,
    tail_cap: usize,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: u64,
}

impl BoundedCapture {
    pub fn new(bound: usize) -> Self {
        let head_cap = bound / 2;
        Self {
            head_cap,
            tail_cap: bound - head_cap,
            head: Vec::with_capacity(head_cap.min(64 * 1024)),
            tail: VecDeque::with_capacity((bound - head_cap).min(64 * 1024)),
            total: 0,
        }
    }

    pub fn push(&mut self, mut bytes: &[u8]) {
        self.total += bytes.len() as u64;
        if self.head.len() < self.head_cap {
            let take = (self.head_cap - self.head.len()).min(bytes.len());
            self.head.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        if bytes.len() >= self.tail_cap {
            self.tail.clear();
            self.tail
                .extend(bytes[bytes.len() - self.tail_cap..].iter().copied());
            return;
        }
        let overflow = (self.tail.len() + bytes.len()).saturating_sub(self.tail_cap);
        self.tail.drain(..overflow);
        self.tail.extend(bytes.iter().copied());
    }

    pub fn finish(self) -> CapturedStream {
        let kept = (self.head.len() + self.tail.len()) as u64;
        let omitted = self.total - kept;
        let tail: Vec<u8> = self.tail.into_iter().collect();
        let text = if omitted == 0 {
            let mut all = self.head;
            all.extend_from_slice(&tail);
            String::from_utf8_lossy(&all).into_owned()
        } else {
            format!(
                "{}\n[... {omitted} bytes omitted by Kin ...]\n{}",
                String::from_utf8_lossy(&self.head),
                String::from_utf8_lossy(&tail)
            )
        };
        CapturedStream {
            text,
            total_bytes: self.total,
            omitted_bytes: omitted,
        }
    }
}

/// One stream as it comes back: the kept text, how many bytes the command
/// wrote, and how many of them the bound cut.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedStream {
    pub text: String,
    pub total_bytes: u64,
    pub omitted_bytes: u64,
}

impl CapturedStream {
    fn to_json(&self, bound: usize) -> Value {
        let mut value = json!({
            "text": self.text,
            "bytes": self.total_bytes,
            "truncated": self.omitted_bytes > 0,
        });
        if self.omitted_bytes > 0 {
            value["omitted_bytes"] = json!(self.omitted_bytes);
            value["note"] = json!(format!(
                "{} of {} bytes are not shown: the first and last {} bytes are kept, and the \
                 marker in the text shows where the rest was cut. Raise max_output_bytes, up to \
                 {MAX_OUTPUT_BYTES}, to see more.",
                self.omitted_bytes,
                self.total_bytes,
                bound / 2
            ));
        }
        value
    }
}

/// One file change a run handed back, or tried to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathChange {
    pub path: String,
    /// `added`, `modified` or `removed`.
    pub change: String,
}

/// One file change a run's write-back refused, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldPath {
    pub path: String,
    pub change: String,
    /// `build_output`, `generated`, `source_unit` or
    /// `not_a_toolchain_manifest`.
    pub reason: String,
    pub why: String,
}

/// Where a run's write-back stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteBackState {
    /// The command did not succeed, so nothing it wrote was kept.
    NotAttempted,
    /// The session may not write, so nothing the command wrote was kept.
    NotPermitted,
    /// The command wrote nothing the policy admits.
    Unchanged,
    /// Its manifests were admitted and recorded as a change.
    Committed,
    /// Its manifests were admitted, and recording them as a change failed.
    AdmittedNotCommitted,
    /// Handing the write-back to the repository failed; nothing was admitted.
    Failed,
}

/// What became of the files a run wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteBackReport {
    pub state: WriteBackState,
    pub admitted: Vec<PathChange>,
    pub withheld: Vec<WithheldPath>,
    /// Every withheld change, when `withheld` lists only the first of them.
    pub withheld_total: usize,
    pub change_id: Option<String>,
    /// The tree of the head `change_id` left, which the next run of this
    /// session is materialized from.
    pub tree_hash: Option<String>,
    pub carried_pending_files: Vec<String>,
    pub note: String,
}

/// The exact state a command ran on, read from the base record of the
/// session workspace it ran in before the command started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RanOn {
    /// The committed head the workspace was materialized from, `None` on a
    /// branch with no change yet.
    pub change_id: Option<String>,
    /// The workspace tree the command saw.
    pub tree_hash: String,
    pub workspace_generation: u64,
    /// The tree of `change_id`, `None` on an unborn branch.
    pub change_tree_hash: Option<String>,
    /// Whether the workspace held content no change records yet, so the
    /// command saw more than `change_id` alone.
    pub uncommitted: bool,
}

impl WriteBackReport {
    pub fn with_state(state: WriteBackState, note: impl Into<String>) -> Self {
        Self {
            state,
            admitted: Vec::new(),
            withheld: Vec::new(),
            withheld_total: 0,
            change_id: None,
            tree_hash: None,
            carried_pending_files: Vec::new(),
            note: note.into(),
        }
    }
}

/// A command that ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecReport {
    pub languages: Vec<Language>,
    /// The state the command ran on. `None` only when the workspace's base
    /// record could not be read.
    pub ran_on: Option<RanOn>,
    /// `None` when the command was stopped, by the timeout or by a signal.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub elapsed: Duration,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub write_back: WriteBackReport,
}

/// What the launcher made of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecOutcome {
    /// The command ran.
    Ran(ExecReport),
    /// The command was refused before it ran, once the project was known.
    Refused {
        refusal: CommandRefusal,
        policy: CommandPolicy,
    },
    /// The session named cannot run commands.
    SessionRefused(String),
    /// Kin could not get as far as running it.
    Failed(String),
}

/// What the launcher hands the server to run one call.
pub type SessionExecutor =
    Arc<dyn Fn(ExecRequest) -> Pin<Box<dyn Future<Output = ExecOutcome> + Send>> + Send + Sync>;

static EXECUTOR: OnceLock<SessionExecutor> = OnceLock::new();

/// Install the launcher's executor for this process. The first one wins.
pub fn install_executor(executor: SessionExecutor) {
    let _ = EXECUTOR.set(executor);
}

/// How the caller reached the tool, which decides the shape of the one call
/// that works a refusal carries: a client holding the routed tool calls a
/// command, and a client holding named tools calls the tool by its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallForm {
    /// `kin_session_exec` by its registered name, as `agent-default` and
    /// `full` serve it.
    Named,
    /// The routed tool's `exec` command.
    Routed,
}

/// Answer one call: check its arguments and the command, and run it through
/// the installed executor.
pub async fn handle(arguments: &HashMap<String, Value>, form: CallForm) -> ToolCallResult {
    handle_with(arguments, EXECUTOR.get(), form).await
}

/// [`handle`] with the executor passed in, so tests run it without a process
/// global.
pub async fn handle_with(
    arguments: &HashMap<String, Value>,
    executor: Option<&SessionExecutor>,
    form: CallForm,
) -> ToolCallResult {
    let request = match parse_request(arguments) {
        Ok(request) => request,
        Err(problem) => {
            let session = arguments
                .get("session_id")
                .and_then(Value::as_str)
                .unwrap_or("<session_id from kin_session_start>");
            return error_answer(json!({
                "state": "refused",
                "message": problem,
                "example": example_call(session, &CommandPolicy::default().example_argv(), form),
            }));
        }
    };
    if let Some(refusal) =
        refuse_before_running(&request.argv).or_else(|| refuse_toolchain_flags(&request.argv))
    {
        return refused_answer(&request, &refusal, None, form);
    }
    if let Some(reason) = request
        .env
        .iter()
        .find_map(|(name, _)| refused_environment(name))
    {
        let refusal = CommandRefusal::new(RefusalKind::RefusedEnvironment, reason);
        return refused_answer(&request, &refusal, None, form);
    }
    let Some(executor) = executor else {
        return error_answer(json!({
            "state": "unavailable",
            "message": "kin_session_exec is answered by the Kin MCP server a client launches, \
                        which runs commands in session workspaces. This server was not given a \
                        way to run one.",
        }));
    };
    answer(&request, executor(request.clone()).await, form)
}

/// One call that works, in the form the caller holds.
fn example_call(session_id: &str, argv: &[String], form: CallForm) -> Value {
    let args = json!({"session_id": session_id, "argv": argv});
    match form {
        CallForm::Named => json!({"name": TOOL_NAME, "arguments": args}),
        CallForm::Routed => json!({"command": "exec", "args": args}),
    }
}

/// The session a refused call needs, opened in the form the caller holds.
fn session_example(form: CallForm) -> Value {
    let args = json!({
        "vendor": "<your client>",
        "client_name": "<your client>",
        "cwd": "<the repository folder>",
        "capabilities": {"can_write": true, "can_commit": true, "can_execute": true}
    });
    match form {
        CallForm::Named => json!({"name": "kin_session_start", "arguments": args}),
        CallForm::Routed => json!({"command": "session", "args": args}),
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn error_answer(value: Value) -> ToolCallResult {
    ToolCallResult::error(pretty(&value))
}

/// The answer for a command refused before it ran.
fn refused_answer(
    request: &ExecRequest,
    refusal: &CommandRefusal,
    policy: Option<&CommandPolicy>,
    form: CallForm,
) -> ToolCallResult {
    let fallback = CommandPolicy {
        languages: Language::ALL.to_vec(),
        ..CommandPolicy::default()
    };
    let shown = policy.unwrap_or(&fallback);
    let mut value = json!({
        "state": "refused",
        "argv": request.argv,
        "refusal": refusal.kind,
        "message": refusal.reason,
        "ran": false,
        "configurable": refusal.kind.configurable(),
        "example": example_call(&request.session_id, &shown.example_argv(), form),
    });
    if let Some(policy) = policy {
        value["languages"] = json!(policy
            .languages
            .iter()
            .map(|language| language.name())
            .collect::<Vec<_>>());
        value["allowed"] = json!(policy.allowed());
    }
    if refusal.kind.configurable() {
        value["configure"] = json!(
            "Add the command's first words to allow under [execution.agent] in .kin/config.toml, \
             for example allow = [\"make test\"]. Shells, command runners, inline code and file \
             utilities stay refused whatever it says."
        );
    }
    error_answer(value)
}

/// The answer for one call the executor handled.
pub fn answer(request: &ExecRequest, outcome: ExecOutcome, form: CallForm) -> ToolCallResult {
    match outcome {
        ExecOutcome::Refused { refusal, policy } => {
            refused_answer(request, &refusal, Some(&policy), form)
        }
        ExecOutcome::SessionRefused(message) => error_answer(json!({
            "state": "refused",
            "argv": request.argv,
            "ran": false,
            "message": message,
            "example": session_example(form),
        })),
        ExecOutcome::Failed(message) => error_answer(json!({
            "state": "failed",
            "argv": request.argv,
            "message": message,
        })),
        ExecOutcome::Ran(report) => ran_answer(request, report),
    }
}

fn ran_answer(request: &ExecRequest, report: ExecReport) -> ToolCallResult {
    let succeeded = report.exit_code == Some(0) && !report.timed_out;
    let state = if report.timed_out {
        "timed_out"
    } else if succeeded {
        "succeeded"
    } else {
        "failed"
    };
    let mut write_back = json!({
        "state": report.write_back.state,
        "admitted": report.write_back.admitted,
        "withheld": report.write_back.withheld,
        "note": report.write_back.note,
    });
    if report.write_back.withheld_total > report.write_back.withheld.len() {
        write_back["withheld_total"] = json!(report.write_back.withheld_total);
    }
    if let Some(change_id) = &report.write_back.change_id {
        write_back["change_id"] = json!(change_id);
    }
    if let Some(tree_hash) = &report.write_back.tree_hash {
        write_back["tree_hash"] = json!(tree_hash);
    }
    if !report.write_back.carried_pending_files.is_empty() {
        write_back["carried_pending_files"] = json!(report.write_back.carried_pending_files);
    }
    let mut value = json!({
        "state": state,
        "argv": request.argv,
        "exit_code": report.exit_code,
        "elapsed_ms": report.elapsed.as_millis() as u64,
        "timeout_secs": request.timeout.as_secs(),
        "ran_on": report.ran_on,
        "languages": report
            .languages
            .iter()
            .map(|language| language.name())
            .collect::<Vec<_>>(),
        "stdout": report.stdout.to_json(request.max_output_bytes),
        "stderr": report.stderr.to_json(request.max_output_bytes),
        "write_back": write_back,
    });
    if report.timed_out {
        value["note"] = json!(format!(
            "The command was still running after {} s and was stopped, with every process it \
             started. Raise timeout_secs, up to {MAX_TIMEOUT_SECS}, for a longer run.",
            request.timeout.as_secs()
        ));
    }
    if report
        .write_back
        .withheld
        .iter()
        .any(|withheld| withheld.reason == "source_unit")
    {
        value["next_step"] = json!(
            "Source the command wrote was not kept. Change code with kin_mutate, then run the \
             command again."
        );
    }
    ToolCallResult::text(pretty(&value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_string).collect()
    }

    fn policy(languages: &[Language]) -> CommandPolicy {
        CommandPolicy {
            languages: languages.to_vec(),
            ..CommandPolicy::default()
        }
    }

    fn args(value: Value) -> HashMap<String, Value> {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn shells_inline_code_and_file_utilities_are_refused_before_anything_runs() {
        for (command, kind) in [
            ("sh -c true", RefusalKind::Shell),
            ("/bin/bash -lc true", RefusalKind::Shell),
            ("zsh", RefusalKind::Shell),
            ("cmd.exe /C dir", RefusalKind::Shell),
            ("env cat main.go", RefusalKind::CommandRunner),
            ("xargs cat", RefusalKind::CommandRunner),
            ("npx some-tool", RefusalKind::CommandRunner),
            ("cat main.go", RefusalKind::FileDump),
            ("/usr/bin/head -n 5 main.go", RefusalKind::FileDump),
            ("sed -n 1,5p main.go", RefusalKind::FileDump),
            ("awk 1 main.go", RefusalKind::FileDump),
            ("xxd main.go", RefusalKind::FileDump),
            ("cp main.go other.go", RefusalKind::FileDump),
            ("tee out.txt", RefusalKind::FileDump),
            ("dd if=main.go", RefusalKind::FileDump),
            ("strings app", RefusalKind::FileDump),
            ("python3 -c print(1)", RefusalKind::InlineCode),
            ("python -Bc print(1)", RefusalKind::InlineCode),
            ("python3 -", RefusalKind::InlineCode),
            ("python3", RefusalKind::InlineCode),
            ("node -e console.log(1)", RefusalKind::InlineCode),
            ("node --eval=1", RefusalKind::InlineCode),
            ("node -p 1", RefusalKind::InlineCode),
            ("perl -e print", RefusalKind::InlineCode),
            ("ruby -e puts", RefusalKind::InlineCode),
            ("go build -o /tmp/app .", RefusalKind::PathOutsideWorkspace),
            ("go run ../other", RefusalKind::PathOutsideWorkspace),
            (
                "go test -coverprofile=/tmp/c.out ./...",
                RefusalKind::PathOutsideWorkspace,
            ),
            ("node ~/x.js", RefusalKind::PathOutsideWorkspace),
        ] {
            let refusal = refuse_before_running(&words(command))
                .unwrap_or_else(|| panic!("{command} was not refused"));
            assert_eq!(refusal.kind, kind, "{command}: {}", refusal.reason);
            assert!(!refusal.kind.configurable(), "{command}");
            // And no configuration can allow it.
            let mut configured = policy(&Language::ALL);
            configured.extra.push(words(command));
            assert_eq!(admit(&words(command), &configured).unwrap_err().kind, kind);
        }
    }

    #[test]
    fn each_language_runs_its_toolchain_entry_points() {
        let go = policy(&[Language::Go]);
        for command in [
            "go build ./...",
            "go test ./...",
            "go test -run TestX -v ./...",
            "go vet ./...",
            "go run .",
            "go run . -exec not-a-go-flag",
            "go list -m",
            "go mod init example.com/app",
            "go mod tidy",
            "go build -o bin/app .",
        ] {
            assert_eq!(admit(&words(command), &go), Ok(()), "{command}");
        }
        for (command, kind) in [
            ("go generate ./...", RefusalKind::NotAllowed),
            ("go mod edit -replace x=y", RefusalKind::NotAllowed),
            ("go build -toolexec cat ./...", RefusalKind::RefusedFlag),
            ("go test -exec=./runner ./...", RefusalKind::RefusedFlag),
            ("go vet -vettool=x ./...", RefusalKind::RefusedFlag),
            ("go env -w GOFLAGS=-x", RefusalKind::RefusedFlag),
            ("npm test", RefusalKind::NotAllowed),
            ("/usr/local/go/bin/go build", RefusalKind::NotAllowed),
        ] {
            assert_eq!(
                admit(&words(command), &go).unwrap_err().kind,
                kind,
                "{command}"
            );
        }

        let node = policy(&[Language::Node]);
        for command in [
            "npm test",
            "npm run build",
            "npm install",
            "npm ci",
            "node src/index.js",
        ] {
            assert_eq!(admit(&words(command), &node), Ok(()), "{command}");
        }
        for (command, kind) in [
            ("npm install -g left-pad", RefusalKind::RefusedFlag),
            (
                "npm run --script-shell=bash build",
                RefusalKind::RefusedFlag,
            ),
            ("npm exec foo", RefusalKind::NotAllowed),
            ("npm run", RefusalKind::NotAllowed),
            ("node --require x src/index.js", RefusalKind::RefusedFlag),
            ("node README.md", RefusalKind::NotAllowed),
        ] {
            assert_eq!(
                admit(&words(command), &node).unwrap_err().kind,
                kind,
                "{command}"
            );
        }

        let python = CommandPolicy {
            languages: vec![Language::Python],
            python_modules: vec!["app".to_string()],
            ..CommandPolicy::default()
        };
        for command in [
            "python -m pytest -q",
            "python3 -m unittest discover",
            "python3.12 -m app",
            "python -m app.cli serve",
            "pytest tests",
        ] {
            assert_eq!(admit(&words(command), &python), Ok(()), "{command}");
        }
        for (command, kind) in [
            ("python3 -m base64 main.py", RefusalKind::FileDump),
            ("python3 -m json.tool data.json", RefusalKind::FileDump),
            ("python3 -m http.server", RefusalKind::FileDump),
            ("python3 -m pip install x", RefusalKind::FileDump),
            ("python3 -m venv .venv", RefusalKind::NotAllowed),
            ("python3 app.py", RefusalKind::NotAllowed),
        ] {
            assert_eq!(
                admit(&words(command), &python).unwrap_err().kind,
                kind,
                "{command}"
            );
        }

        let rust = policy(&[Language::Rust]);
        for command in [
            "cargo build",
            "cargo test --workspace",
            "cargo +nightly check",
            "cargo run -- --help",
        ] {
            assert_eq!(admit(&words(command), &rust), Ok(()), "{command}");
        }
        for (command, kind) in [
            ("cargo install ripgrep", RefusalKind::NotAllowed),
            (
                "cargo --config target.x.runner=sh test",
                RefusalKind::RefusedFlag,
            ),
            ("cargo -Zunstable-options build", RefusalKind::RefusedFlag),
        ] {
            assert_eq!(
                admit(&words(command), &rust).unwrap_err().kind,
                kind,
                "{command}"
            );
        }
    }

    /// A value-taking flag never ends the scan early: every word of an
    /// admitted Go command is read against its subcommand's grammar, so a
    /// denied flag after a flag's value is found, and a flag the grammar does
    /// not know is refused rather than guessed at.
    #[test]
    fn go_flags_are_read_by_grammar_so_a_value_cannot_hide_a_denied_flag() {
        let go = policy(&[Language::Go]);
        let argv = |words: &[&str]| {
            words
                .iter()
                .map(|word| word.to_string())
                .collect::<Vec<_>>()
        };
        for (command, kind) in [
            (
                argv(&["go", "run", "-tags", "review", "-exec", "cat main.go", "."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "run", "-tags=review", "--exec=cat", "."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "build", "-tags", "x", "-toolexec", "cat", "./..."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "test", "-run", "TestX", "-toolexec=cat", "./..."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "vet", "-tags", "x", "-vettool", "cat", "./..."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "test", "-test.exec=cat", "./..."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "build", "-ldflags=-extld=sh", "."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&[
                    "go",
                    "build",
                    "-ldflags",
                    "-linkmode external -extldflags -fuse-ld=x",
                    ".",
                ]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "build", "-gcflags", "-importcfg=cfg", "."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "build", "-unknown-flag", "."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "vet", "-printf.funcs=Logf", "./..."]),
                RefusalKind::RefusedFlag,
            ),
            (argv(&["go", "build", "-o"]), RefusalKind::RefusedFlag),
            (
                argv(&["go", "mod", "init", "-modfile=x", "m"]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "mod", "tidy", "-modfile", "other.mod"]),
                RefusalKind::RefusedFlag,
            ),
        ] {
            let refusal = admit(&command, &go).unwrap_err();
            assert_eq!(refusal.kind, kind, "{command:?}: {}", refusal.reason);
        }
        for command in [
            argv(&[
                "go",
                "run",
                "-tags",
                "review",
                ".",
                "-exec",
                "is the program's own",
            ]),
            argv(&[
                "go",
                "build",
                "-ldflags",
                "-X main.version=1.0",
                "-o",
                "bin/app",
                ".",
            ]),
            argv(&[
                "go", "test", "-count=1", "-run", "TestX", "./...", "-args", "-exec", "x",
            ]),
            argv(&["go", "test", "-v=test2json", "-timeout", "30s", "./..."]),
            argv(&["go", "list", "-m", "-json=Path,Version", "all"]),
            argv(&["go", "mod", "tidy", "-go=1.25", "-v"]),
        ] {
            assert_eq!(admit(&command, &go), Ok(()), "{command:?}");
        }
    }

    /// An agent asks the toolchain what it is before it writes a manifest, so
    /// `go version`, by itself, and a read-only `go env` run by default.
    /// `go version` given a flag or a path would read a binary, and `go env
    /// -w` and `-u` write the user's Go environment file, outside the
    /// workspace, where a `GOFLAGS` would reach every later go command. Each
    /// is refused before anything runs, whatever the repository configures,
    /// as is every `go env` word but a leading `-json` and variable names.
    #[test]
    fn go_version_and_a_read_only_go_env_run_by_default() {
        let go = policy(&[Language::Go]);
        for command in [
            "go version",
            "go env",
            "go env GOPATH",
            "go env GOFLAGS GOPROXY GOTOOLCHAIN GO111MODULE GOPATH GOCACHE",
            "go env -json",
            "go env -json GOVERSION",
            "go env -json GOVERSION GOMOD",
        ] {
            assert_eq!(admit(&words(command), &go), Ok(()), "{command}");
            assert_eq!(refuse_toolchain_flags(&words(command)), None, "{command}");
        }
        let mut configured = policy(&[Language::Go]);
        configured.extra.push(words("go env"));
        configured.extra.push(words("go"));
        for command in [
            "go env -w X=1",
            "go env -w GOFLAGS=-toolexec=cat",
            "go env -u X",
            "go env -w=true X=1",
            "go env --u X",
            "go env -json -w X=1",
            "go env GOPATH -w X=1",
            "go env -C sub GOPATH",
            "go env -x",
            "go env -changed",
            "go env --",
            "go env -- -x",
            "go env -- -unknown",
            "go env -- GOFLAGS",
            "go env --json",
            "go env -json=true",
            "go env -json -json",
            "go env GOVERSION -json",
            "go env X=1",
            "go env gopath",
            "go env 1GO",
            "go version -m bin/app",
            "go version -m -json bin/app",
            "go version -v",
            "go version -v .",
            "go version bin/app",
            "go version .",
            "go version -toolexec cat",
        ] {
            for policy in [&go, &configured] {
                let refusal = admit(&words(command), policy).unwrap_err();
                assert_eq!(
                    refusal.kind,
                    RefusalKind::RefusedFlag,
                    "{command}: {}",
                    refusal.reason
                );
            }
            // The server refuses it before it asks the launcher for anything.
            assert_eq!(
                refuse_toolchain_flags(&words(command)).map(|refusal| refusal.kind),
                Some(RefusalKind::RefusedFlag),
                "{command}"
            );
        }
        let writes = admit(&words("go env -w GOFLAGS=-x"), &go).unwrap_err();
        assert!(
            writes.reason.contains("Go environment file"),
            "{}",
            writes.reason
        );
        for (command, kind) in [
            (
                "go version -m /usr/local/bin/app",
                RefusalKind::PathOutsideWorkspace,
            ),
            ("go version ../app", RefusalKind::PathOutsideWorkspace),
            ("go generate ./...", RefusalKind::NotAllowed),
        ] {
            assert_eq!(
                admit(&words(command), &go).unwrap_err().kind,
                kind,
                "{command}"
            );
        }
        // A project not written in Go does not run them.
        let node = policy(&[Language::Node]);
        assert_eq!(
            admit(&words("go version"), &node).unwrap_err().kind,
            RefusalKind::NotAllowed
        );
        // And the refusal names them among what the project runs.
        let refusal = admit(&words("make test"), &go).unwrap_err();
        for entry in ["go version", "go env"] {
            assert!(refusal.reason.contains(entry), "{}", refusal.reason);
        }
    }

    /// A configured prefix adds a command. It never lifts a language's own
    /// refusals, so allowing `go` or `npm` does not allow the wrapper routes.
    #[test]
    fn a_configured_prefix_never_lifts_a_language_refusal() {
        let mut configured = policy(&[
            Language::Go,
            Language::Node,
            Language::Python,
            Language::Rust,
        ]);
        for prefix in ["go", "go generate", "npm", "node", "python3", "cargo"] {
            configured.extra.push(words(prefix));
        }
        assert_eq!(admit(&words("go generate ./..."), &configured), Ok(()));
        assert_eq!(admit(&words("npm exec eslint"), &configured), Ok(()));
        let argv = |words: &[&str]| {
            words
                .iter()
                .map(|word| word.to_string())
                .collect::<Vec<_>>()
        };
        for (command, kind) in [
            (
                argv(&["go", "run", "-exec", "cat", "."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "generate", "-toolexec=cat", "./..."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "run", "-tags", "x", "-exec", "cat main.go", "."]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["npm", "exec", "--script-shell=bash", "x"]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["npm", "install", "-g", "x"]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["node", "--require", "x.js", "a.js"]),
                RefusalKind::RefusedFlag,
            ),
            (argv(&["node", "-e", "1"]), RefusalKind::InlineCode),
            (
                argv(&["python3", "-m", "base64", "main.py"]),
                RefusalKind::FileDump,
            ),
            (argv(&["python3", "-c", "1"]), RefusalKind::InlineCode),
            (
                argv(&["cargo", "--config", "x=1", "install", "y"]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["cargo", "-Zunstable-options", "build"]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "env", "-w", "GOFLAGS=-toolexec=cat"]),
                RefusalKind::RefusedFlag,
            ),
            (
                argv(&["go", "env", "-u", "GOFLAGS"]),
                RefusalKind::RefusedFlag,
            ),
        ] {
            let refusal = admit(&command, &configured).unwrap_err();
            assert_eq!(refusal.kind, kind, "{command:?}: {}", refusal.reason);
        }
    }

    #[test]
    fn only_plain_application_variables_may_be_set() {
        for denied in [
            "PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "GOFLAGS",
            "GoToolchain",
            "GOPROXY",
            "GOENV",
            "GOROOT",
            "GOPATH",
            "GOCACHE",
            "GOMODCACHE",
            "CGO_ENABLED",
            "CGO_LDFLAGS",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "RUSTFLAGS",
            "RUSTC_WRAPPER",
            "CARGO_HOME",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "SHELL",
            "IFS",
            "BASH_ENV",
            "ENV",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "npm_config_script_shell",
            "GIT_SSH_COMMAND",
            "KIN_SESSION_ID",
            "HOME",
            "1BAD",
            "A=B",
            "",
        ] {
            assert!(
                refused_environment(denied).is_some(),
                "{denied} was allowed"
            );
        }
        for allowed in [
            "TASKS_FILE",
            "NODE_ENV",
            "GOOGLE_API_KEY",
            "APP_PORT",
            "_X",
            "RUST_BACKTRACE",
        ] {
            assert_eq!(refused_environment(allowed), None, "{allowed}");
        }
    }

    #[tokio::test]
    async fn an_environment_variable_reaches_the_executor_only_when_it_is_plain() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let executor: SessionExecutor = Arc::new(move |request: ExecRequest| {
            record.lock().unwrap().push(request.env.clone());
            Box::pin(async { ExecOutcome::Failed("recorded".into()) })
        });
        let refused = handle_with(
            &args(json!({"session_id": "s", "argv": ["go", "run", "."], "env": {"TASKS_FILE": "t.json", "GOFLAGS": "-toolexec=cat"}})),
            Some(&executor),
            CallForm::Routed,
        )
        .await;
        assert_eq!(refused.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = &refused.content[0];
        let answer: Value = serde_json::from_str(text).unwrap();
        assert_eq!(answer["refusal"], "refused_environment");
        assert_eq!(answer["ran"], false);
        assert!(seen.lock().unwrap().is_empty());

        handle_with(
            &args(json!({"session_id": "s", "argv": ["go", "run", ".", "add", "milk"], "env": {"TASKS_FILE": "$HOME/t.json"}})),
            Some(&executor),
            CallForm::Routed,
        )
        .await;
        assert_eq!(
            *seen.lock().unwrap(),
            vec![vec![("TASKS_FILE".to_string(), "$HOME/t.json".to_string())]]
        );
        let bad = parse_request(&args(
            json!({"session_id": "s", "argv": ["go"], "env": {"N": 1}}),
        ));
        assert!(bad.unwrap_err().contains("plain strings"));
    }

    #[test]
    fn configuration_adds_commands_and_says_how_in_every_refusal() {
        let mut configured = policy(&[Language::Go]);
        assert_eq!(
            admit(&words("make test"), &configured).unwrap_err().kind,
            RefusalKind::NotAllowed
        );
        let refusal = admit(&words("make test"), &configured).unwrap_err();
        assert!(
            refusal.reason.contains("[execution.agent]"),
            "{}",
            refusal.reason
        );
        assert!(refusal.reason.contains("go test"), "{}", refusal.reason);
        configured.extra.push(words("make test"));
        assert_eq!(admit(&words("make test"), &configured), Ok(()));
        assert_eq!(admit(&words("make test unit"), &configured), Ok(()));
        assert_eq!(
            admit(&words("make deploy"), &configured).unwrap_err().kind,
            RefusalKind::NotAllowed
        );
        // A language the project is not written in is not allowed.
        assert_eq!(
            admit(&words("cargo build"), &configured).unwrap_err().kind,
            RefusalKind::NotAllowed
        );
    }

    #[test]
    fn output_keeps_both_ends_and_says_how_much_it_cut() {
        let mut small = BoundedCapture::new(64);
        small.push(b"ok\n");
        let small = small.finish();
        assert_eq!(small.text, "ok\n");
        assert_eq!(small.omitted_bytes, 0);

        let mut large = BoundedCapture::new(20);
        for chunk in [
            b"0123456789".as_slice(),
            b"abcdefghij",
            b"KLMNOPQRST",
            b"uvwxyz",
        ] {
            large.push(chunk);
        }
        let large = large.finish();
        assert_eq!(large.total_bytes, 36);
        assert_eq!(large.omitted_bytes, 16);
        assert!(large
            .text
            .starts_with("0123456789\n[... 16 bytes omitted by Kin ...]\n"));
        assert!(large.text.ends_with("QRSTuvwxyz"), "{}", large.text);

        // Exactly the bound is kept whole, across chunk boundaries.
        let mut exact = BoundedCapture::new(10);
        exact.push(b"01234");
        exact.push(b"56789");
        let exact = exact.finish();
        assert_eq!(exact.text, "0123456789");
        assert_eq!(exact.omitted_bytes, 0);

        let shown = large.to_json(20);
        assert_eq!(shown["truncated"], true);
        assert_eq!(shown["omitted_bytes"], 16);
        assert!(shown["note"].as_str().unwrap().contains("max_output_bytes"));
    }

    #[test]
    fn arguments_are_checked_before_anything_runs() {
        let good = parse_request(&args(json!({
            "session_id": "s", "argv": ["go", "test"], "timeout_secs": 5, "max_output_bytes": 300
        })))
        .unwrap();
        assert_eq!(good.timeout, Duration::from_secs(5));
        assert_eq!(good.max_output_bytes, 300);
        let defaulted = parse_request(&args(json!({"session_id": "s", "argv": ["go"]}))).unwrap();
        assert_eq!(defaulted.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert_eq!(defaulted.max_output_bytes, DEFAULT_OUTPUT_BYTES as usize);
        for (bad, needle) in [
            (json!({"argv": ["go"]}), "needs session_id"),
            (
                json!({"session_id": "s", "argv": "go test ./..."}),
                "not one string",
            ),
            (
                json!({"session_id": "s", "argv": []}),
                "at least the program",
            ),
            (json!({"session_id": "s", "argv": [1]}), "array of strings"),
            (
                json!({"session_id": "s", "argv": ["go"], "timeout_secs": 0}),
                "from 1 to 600",
            ),
            (
                json!({"session_id": "s", "argv": ["go"], "shell": true}),
                "does not take shell",
            ),
        ] {
            let problem = parse_request(&args(bad.clone())).unwrap_err();
            assert!(problem.contains(needle), "{bad}: {problem}");
        }
    }

    #[tokio::test]
    async fn a_refused_command_never_reaches_the_executor() {
        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = Arc::clone(&reached);
        let executor: SessionExecutor = Arc::new(move |_request| {
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { ExecOutcome::Failed("should not run".into()) })
        });
        for argv in [
            json!(["sh", "-c", "cat main.go"]),
            json!(["cat", "main.go"]),
            json!(["python3", "-c", "print(open('main.go').read())"]),
            json!(["go", "run", "-tags", "review", "-exec", "cat main.go", "."]),
            json!(["go", "build", "-toolexec", "cat", "./..."]),
            json!(["go", "vet", "-vettool=/bin/cat", "./..."]),
            json!(["npm", "run", "--script-shell", "bash", "build"]),
            json!(["python3", "-m", "json.tool", "data.json"]),
        ] {
            for form in [CallForm::Routed, CallForm::Named] {
                let result = handle_with(
                    &args(json!({"session_id": "s", "argv": argv})),
                    Some(&executor),
                    form,
                )
                .await;
                assert_eq!(result.is_error, Some(true));
                let crate::types::ContentBlock::Text { text } = &result.content[0];
                let answer: Value = serde_json::from_str(text).unwrap();
                assert_eq!(answer["state"], "refused");
                assert_eq!(answer["ran"], false);
                // The call that works is in the form the caller holds.
                match form {
                    CallForm::Routed => assert_eq!(answer["example"]["command"], "exec"),
                    CallForm::Named => {
                        assert_eq!(answer["example"]["name"], TOOL_NAME);
                        assert!(answer["example"]["arguments"]["argv"].is_array());
                    }
                }
            }
        }
        assert!(!reached.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// `go version` and a read-only `go env` reach the launcher to run; every
    /// other form of `go env`, its writes included, is answered by the server
    /// as refused and never reaches it.
    #[tokio::test]
    async fn go_env_refusals_never_reach_the_executor_and_its_reads_do() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let executor: SessionExecutor = Arc::new(move |request: ExecRequest| {
            record.lock().unwrap().push(request.argv.clone());
            Box::pin(async { ExecOutcome::Failed("recorded".into()) })
        });
        for argv in [
            json!(["go", "env", "-w", "X=1"]),
            json!(["go", "env", "-u", "X"]),
            json!(["go", "env", "-w", "GOFLAGS=-toolexec=cat"]),
            json!(["go", "env", "-json", "-w", "X=1"]),
            json!(["go", "env", "-x"]),
            json!(["go", "env", "--", "-x"]),
            json!(["go", "env", "--", "GOFLAGS"]),
            json!(["go", "version", "-m", "."]),
        ] {
            for form in [CallForm::Routed, CallForm::Named] {
                let result = handle_with(
                    &args(json!({"session_id": "s", "argv": argv})),
                    Some(&executor),
                    form,
                )
                .await;
                assert_eq!(result.is_error, Some(true));
                let crate::types::ContentBlock::Text { text } = &result.content[0];
                let answer: Value = serde_json::from_str(text).unwrap();
                assert_eq!(answer["state"], "refused", "{argv}");
                assert_eq!(answer["refusal"], "refused_flag", "{argv}");
                assert_eq!(answer["ran"], false, "{argv}");
                assert_eq!(answer["configurable"], false, "{argv}");
            }
        }
        assert!(seen.lock().unwrap().is_empty());
        let reads = [
            json!(["go", "version"]),
            json!(["go", "env"]),
            json!(["go", "env", "GOPATH", "GOFLAGS"]),
            json!(["go", "env", "-json", "GOVERSION"]),
        ];
        for argv in &reads {
            handle_with(
                &args(json!({"session_id": "s", "argv": argv})),
                Some(&executor),
                CallForm::Named,
            )
            .await;
        }
        let expected: Vec<Vec<String>> = reads
            .iter()
            .map(|argv| serde_json::from_value(argv.clone()).unwrap())
            .collect();
        assert_eq!(*seen.lock().unwrap(), expected);
    }

    /// Every example a refusal carries runs where it is read: through the
    /// routed tool as a command that dispatches to this tool or to the
    /// session it needs, and on a named connection as a registered tool with
    /// arguments its schema accepts.
    #[test]
    fn every_refusal_example_is_a_call_that_works_where_it_is_read() {
        let request =
            parse_request(&args(json!({"session_id": "s", "argv": ["make", "x"]}))).unwrap();
        let outcomes = || {
            vec![
                ExecOutcome::Refused {
                    refusal: CommandRefusal::new(RefusalKind::NotAllowed, "no"),
                    policy: CommandPolicy {
                        languages: vec![Language::Go],
                        ..CommandPolicy::default()
                    },
                },
                ExecOutcome::SessionRefused("no session".into()),
            ]
        };
        let registry = crate::tools::tool_definitions();
        for form in [CallForm::Routed, CallForm::Named] {
            for outcome in outcomes() {
                let result = answer(&request, outcome, form);
                let crate::types::ContentBlock::Text { text } = &result.content[0];
                let example = serde_json::from_str::<Value>(text).unwrap()["example"].clone();
                match form {
                    CallForm::Routed => {
                        let mut params: crate::types::ToolCallParams =
                            serde_json::from_value(json!({
                                "name": crate::routed::TOOL_NAME,
                                "arguments": example,
                            }))
                            .unwrap();
                        let routed = crate::routed::route(
                            &mut params,
                            Some(crate::routed::RoutedSurface::WITH_WRITES),
                        );
                        assert!(
                            matches!(routed, crate::routed::Routing::Dispatch),
                            "{example} does not dispatch: {routed:?}"
                        );
                    }
                    CallForm::Named => {
                        let name = example["name"].as_str().unwrap();
                        let schema = &registry
                            .tools
                            .iter()
                            .find(|tool| tool.name == name)
                            .unwrap_or_else(|| panic!("{name} is not registered"))
                            .input_schema;
                        for key in example["arguments"].as_object().unwrap().keys() {
                            assert!(
                                schema["properties"].get(key).is_some(),
                                "{name} does not take {key}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn a_run_answers_with_exit_code_time_and_bounded_output() {
        let executor: SessionExecutor = Arc::new(|request: ExecRequest| {
            Box::pin(async move {
                let mut stdout = BoundedCapture::new(request.max_output_bytes);
                stdout.push(&vec![b'x'; 1000]);
                ExecOutcome::Ran(ExecReport {
                    languages: vec![Language::Go],
                    ran_on: Some(RanOn {
                        change_id: Some("c1".into()),
                        tree_hash: "t1".into(),
                        workspace_generation: 3,
                        change_tree_hash: Some("t1".into()),
                        uncommitted: false,
                    }),
                    exit_code: Some(1),
                    timed_out: false,
                    elapsed: Duration::from_millis(1234),
                    stdout: stdout.finish(),
                    stderr: CapturedStream::default(),
                    write_back: WriteBackReport::with_state(
                        WriteBackState::NotAttempted,
                        "The command exited 1, so nothing it wrote was kept.",
                    ),
                })
            })
        });
        let result = handle_with(
            &args(json!({"session_id": "s", "argv": ["go", "test", "./..."], "max_output_bytes": 256})),
            Some(&executor),
            CallForm::Routed,
        )
        .await;
        assert_ne!(result.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = &result.content[0];
        let answer: Value = serde_json::from_str(text).unwrap();
        assert_eq!(answer["state"], "failed");
        assert_eq!(answer["exit_code"], 1);
        assert_eq!(answer["elapsed_ms"], 1234);
        assert_eq!(answer["stdout"]["bytes"], 1000);
        assert_eq!(answer["stdout"]["truncated"], true);
        assert_eq!(answer["stdout"]["omitted_bytes"], 744);
        assert_eq!(answer["write_back"]["state"], "not_attempted");
        assert_eq!(answer["ran_on"]["change_id"], "c1");
        assert_eq!(answer["ran_on"]["tree_hash"], "t1");
        assert_eq!(answer["ran_on"]["workspace_generation"], 3);
    }

    fn argv_of(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    /// Commands whose Go target is not the repository's own code, each of
    /// which the server refuses before it asks the launcher for anything.
    fn go_targets_outside_any_repository() -> Vec<Vec<String>> {
        [
            // The observed whole-file read: gofmt given two committed files.
            &[
                "go",
                "run",
                "cmd/gofmt",
                "main.go",
                "internal/store/store.go",
            ][..],
            &["go", "run", "cmd/gofmt", "-l", "-d", "."],
            &["go", "run", "cmd/vet", "."],
            &["go", "run", "cmd/doc", "fmt"],
            &["go", "run", "cmd/objdump", "app"],
            &["go", "run", "std"],
            &["go", "run", "cmd"],
            &["go", "run", "fmt"],
            &["go", "run", "golang.org/x/tools/cmd/stringer@latest"],
            &["go", "run", "example.com/app@v1.0.0"],
            &["go", "run", "./cmd/app@v1.0.0"],
            &["go", "run", "../outside"],
            &["go", "run", "/abs/path/x.go"],
            &["go", "run", "main.go", "/etc/passwd"],
            &["go", "run", "-tags", "x", "cmd/gofmt", "f.go"],
            &["go", "run", "-tags=x", "cmd/gofmt"],
            &["go", "run", "--", "cmd/gofmt", "f.go"],
            &["go", "run", "-tags", "x", "--", "cmd/gofmt", "-l", "."],
            &["go", "run", "-C", "sub", "cmd/gofmt", "main.go"],
            &["go", "run", "-C", "sub", "example.com/app/cmd/x"],
            &["go", "run", "./vendor/golang.org/x/tools/cmd/stringer"],
            &["go", "run", "..."],
            &["go", "test", "cmd/gofmt"],
            &["go", "test", "std"],
            &["go", "test", "all"],
            &["go", "test", "./...", "cmd/..."],
            &["go", "test", "-run", "X", "cmd/gofmt"],
            &["go", "-C", "sub", "run", "cmd/gofmt", "main.go"],
            &["go", "-C=sub", "run", "--", "cmd/gofmt", "main.go"],
            &["go", "-C", "sub", "test", "std"],
            &["go", "-C", "../x", "run", "."],
            &["go", "vet", "std"],
            &["go", "vet", "cmd/gofmt"],
            &["go", "build", "cmd/..."],
            &["go", "build", "-o", "bin/gofmt", "cmd/gofmt"],
            &["go", "build", "--", "std"],
            &["go", "build", "golang.org/x/tools/...@latest"],
        ]
        .iter()
        .map(|words| argv_of(words))
        .collect()
    }

    /// `go run` runs the repository's own main package, and `go build`, `go
    /// test` and `go vet` take the repository's own packages. A target in the
    /// standard library or the toolchain's `cmd` tree, a `pkg@version`, a path
    /// outside the workspace, and another module's import path are refused
    /// before anything runs, however the target is reached: after a flag's
    /// value, after `--`, or under a configured `go` or `go run` prefix.
    #[test]
    fn go_targets_outside_the_repository_are_refused_before_anything_runs() {
        let go = policy(&[Language::Go]);
        let mut configured = policy(&[Language::Go]);
        for prefix in ["go", "go run", "go test", "go build", "go vet"] {
            configured.extra.push(words(prefix));
        }
        let mut admitted = Vec::new();
        let mut negatives = go_targets_outside_any_repository();
        // Another module's import path, which only the module path tells
        // apart from the repository's own.
        negatives.push(argv_of(&["go", "build", "golang.org/x/..."]));
        negatives.push(argv_of(&["go", "run", "golang.org/x/tools/cmd/stringer"]));
        for command in &negatives {
            for policy in [&go, &configured] {
                match admit(command, policy) {
                    Ok(()) => admitted.push(command.join(" ")),
                    Err(refusal) => assert!(!refusal.kind.configurable(), "{command:?}"),
                }
            }
        }
        admitted.dedup();
        assert!(
            admitted.is_empty(),
            "admitted a target outside the repository: {admitted:#?}"
        );
    }

    /// Each target outside any repository is refused by the server before it
    /// asks the launcher for anything, so nothing runs, no stdout comes back,
    /// and the refusal quotes no file.
    #[tokio::test]
    async fn a_go_target_outside_the_repository_never_reaches_the_executor() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let executor: SessionExecutor = Arc::new(move |request: ExecRequest| {
            record.lock().unwrap().push(request.argv.join(" "));
            Box::pin(async { ExecOutcome::Failed("recorded".into()) })
        });
        for argv in go_targets_outside_any_repository() {
            for form in [CallForm::Routed, CallForm::Named] {
                let result = handle_with(
                    &args(json!({"session_id": "s", "argv": argv})),
                    Some(&executor),
                    form,
                )
                .await;
                let crate::types::ContentBlock::Text { text } = &result.content[0];
                let answer: Value = serde_json::from_str(text).unwrap();
                if answer["state"] != "refused" {
                    continue;
                }
                assert_eq!(result.is_error, Some(true), "{argv:?}");
                assert_eq!(answer["ran"], false, "{argv:?}");
                assert!(answer.get("stdout").is_none(), "{argv:?}: {text}");
                assert!(answer.get("exit_code").is_none(), "{argv:?}: {text}");
                assert!(!text.contains("package main"), "{argv:?}: {text}");
            }
        }
        let reached = seen.lock().unwrap().clone();
        assert!(
            reached.is_empty(),
            "reached the executor: {:#?}",
            reached.iter().collect::<BTreeSet<_>>()
        );
    }

    /// A repository whose module is example.com/app, and which requires
    /// golang.org/x/tools.
    fn go_module_policy() -> CommandPolicy {
        CommandPolicy {
            languages: vec![Language::Go],
            go: GoModules {
                main: vec![GoModule {
                    path: "example.com/app".into(),
                    dir: ".".into(),
                }],
                other: vec!["golang.org/x/tools".into()],
                unresolved: None,
            },
            ..CommandPolicy::default()
        }
    }

    /// The repository's own packages run, build, test and vet, reached by
    /// path, by `.go` files of one main package, or by the module's import
    /// path, and a `go run` program's own words after its target are free.
    #[test]
    fn go_targets_inside_the_repository_are_admitted() {
        let go = go_module_policy();
        let mut configured = go.clone();
        configured.extra.push(words("go run"));
        for command in [
            &["go", "run", "."][..],
            &["go", "run", ".", "-exec", "user-arg"],
            &["go", "run", ".", "add", "milk", "cmd/gofmt", "main.go"],
            &["go", "run", "./cmd/app"],
            &["go", "run", "./cmd/..."],
            &["go", "run", "example.com/app"],
            &["go", "run", "example.com/app/cmd/x", "--flag"],
            &["go", "run", "main.go", "helper.go"],
            &["go", "run", "main.go", "helper.go", "list", "std"],
            &["go", "run", "cmd/app/main.go"],
            &["go", "run", "-tags", "x", "."],
            &["go", "run", "-tags=x", "./cmd/app"],
            &["go", "run", "--", ".", "-v"],
            &["go", "run", "-C", "sub", "."],
            &["go", "-C", "sub", "run", "."],
            &["go", "-C=sub", "build", "./..."],
            &["go", "test", "./..."],
            &["go", "test", "./...", "--", "label"],
            &["go", "test", "-run", "X", "./...", "-args", "cmd/gofmt"],
            &["go", "test", "example.com/app/..."],
            &["go", "vet", "./..."],
            &["go", "build", "./..."],
            &["go", "build", "example.com/app/internal/store"],
            &["go", "build"],
            &["go", "list", "-m", "all"],
        ] {
            let command = argv_of(command);
            for policy in [&go, &configured] {
                assert_eq!(admit(&command, policy), Ok(()), "{command:?}");
            }
            assert_eq!(refuse_toolchain_flags(&command), None, "{command:?}");
        }
    }

    /// Only the module path tells the repository's own import paths from
    /// another module's, so the launcher's reading of it decides these, and
    /// a module the build requires under the main module's own path is never
    /// the repository's.
    #[test]
    fn an_import_path_is_the_repository_s_only_under_its_own_module() {
        let go = go_module_policy();
        let mut shadowed = go_module_policy();
        shadowed.go.other.push("example.com/app/tools".into());
        let mut unresolved = go_module_policy();
        unresolved.go.unresolved = Some(
            "is an import path, and the go.work uses a directory outside the workspace.".into(),
        );
        let no_module = policy(&[Language::Go]);
        for (command, policy) in [
            (&["go", "run", "golang.org/x/tools/cmd/stringer"][..], &go),
            (&["go", "build", "golang.org/x/..."], &go),
            (&["go", "run", "example.com/other/cmd/x"], &go),
            (&["go", "run", "example.com/application"], &go),
            (&["go", "build", "example.com/app..."], &go),
            (&["go", "run", "example.com/app/tools/cmd/gen"], &shadowed),
            (&["go", "test", "example.com/app/..."], &shadowed),
            (&["go", "run", "example.com/app/cmd/x"], &unresolved),
            (&["go", "run", "example.com/app/cmd/x"], &no_module),
        ] {
            let command = argv_of(command);
            // The server cannot judge these without the module path.
            assert_eq!(refuse_toolchain_flags(&command), None, "{command:?}");
            let refusal = admit(&command, policy).unwrap_err();
            assert_eq!(
                refusal.kind,
                RefusalKind::PackageOutsideRepository,
                "{command:?}: {}",
                refusal.reason
            );
        }
        assert_eq!(
            admit(&argv_of(&["go", "run", "example.com/app/cmd/x"]), &shadowed),
            Ok(())
        );
        for command in [&["go", "run", "."][..], &["go", "build", "./..."]] {
            assert_eq!(admit(&argv_of(command), &unresolved), Ok(()));
            assert_eq!(admit(&argv_of(command), &no_module), Ok(()));
        }
    }

    /// A refusal names what exec runs instead and how a Kin agent reads code,
    /// and quotes nothing of any file.
    #[test]
    fn a_go_target_refusal_says_what_runs_and_how_code_is_read() {
        let refusal = admit(
            &argv_of(&[
                "go",
                "run",
                "cmd/gofmt",
                "main.go",
                "internal/store/store.go",
            ]),
            &go_module_policy(),
        )
        .unwrap_err();
        assert_eq!(refusal.kind, RefusalKind::PackageOutsideRepository);
        assert!(!refusal.kind.configurable());
        for needle in [
            "cmd/gofmt",
            "go run .",
            "./...",
            "get_entity_source",
            "source",
        ] {
            assert!(
                refusal.reason.contains(needle),
                "{needle}: {}",
                refusal.reason
            );
        }
        let versioned = admit(
            &argv_of(&["go", "run", "golang.org/x/tools/cmd/stringer@latest"]),
            &go_module_policy(),
        )
        .unwrap_err();
        assert!(
            versioned.reason.contains("module version"),
            "{}",
            versioned.reason
        );
    }

    /// GOFLAGS the server inherits is read the way argv is: a flag that swaps
    /// the go.mod, overlays files or hands the build to another program is
    /// refused, and ordinary build settings are not.
    #[test]
    fn inherited_goflags_that_change_the_build_are_refused() {
        for goflags in [
            "-modfile=/elsewhere/go.mod",
            "-mod=mod -overlay=/tmp/o.json",
            "-toolexec=cat",
            "--exec=cat",
            "\"-toolexec=cat\"",
            "'-toolexec=cat'",
            "-mod=mod '-ldflags=-extld=sh'",
            "\"-ldflags=-s -w -extld=sh\"",
            "-gcflags=all=-toolexec",
            "-asmflags=-x",
            "-C=sub",
            "\"-tags=a",
            "-tags=a 'x",
            "main.go",
            "-unknown-flag",
        ] {
            let refusal = refused_inherited_goflags(goflags, "the server's environment")
                .unwrap_or_else(|| panic!("{goflags} was not refused"));
            assert_eq!(refusal.kind, RefusalKind::RefusedEnvironment, "{goflags}");
        }
        for goflags in [
            "",
            "-mod=mod",
            "-tags=integration -trimpath",
            "-buildvcs=false",
            "'-tags=a,b'",
            "\"-ldflags=-s -w\" -count=1",
        ] {
            assert_eq!(
                refused_inherited_goflags(goflags, "the server's environment"),
                None,
                "{goflags}"
            );
        }
        assert!(refused_environment("GO111MODULE").is_some());
    }

    #[test]
    fn the_description_and_schema_hold_their_contract() {
        let definition = tool_definition();
        assert!(!definition.description.contains('\u{2014}'));
        assert!(!definition.annotations.read_only_hint);
        assert_eq!(
            definition.input_schema["required"],
            json!(["session_id", "argv"])
        );
        assert_eq!(
            definition.input_schema["additionalProperties"],
            json!(false)
        );
    }
}
