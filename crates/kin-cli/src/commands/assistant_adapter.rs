// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One adapter per assistant CLI, in a registry.
//!
//! The adapter owns the full per-CLI contract: launch program, alias set, and
//! the `--semantic-only` capability profile with a self-declared enforcement
//! tier. `kin with` resolves every assistant it launches through this registry,
//! so the launcher has exactly one answer for which clients exist and what
//! each one can honor.
//!
//! `kin setup`'s registration writers do not resolve through it yet. They carry
//! their own client list and their own per-client config paths, so a client can
//! currently be registerable by `kin setup` and not launchable by `kin with`.
//! Moving those writers onto this registry is the intent; until that lands this
//! registry is authoritative for launching only, and the setup list is
//! authoritative for registration.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// How strongly an adapter can honor `--semantic-only` for its CLI.
///
/// The tier is printed at launch so the operator is never told a profile is
/// enforced when the CLI only received guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementTier {
    /// The CLI's own permission layer refuses the denied tools.
    Enforced,
    /// The CLI receives instructions but nothing refuses a violation.
    Instructed,
    /// No profile exists for this CLI yet; the flag fails closed.
    Unsupported,
}

impl EnforcementTier {
    pub fn as_str(self) -> &'static str {
        match self {
            EnforcementTier::Enforced => "enforced",
            EnforcementTier::Instructed => "instructed",
            EnforcementTier::Unsupported => "unsupported",
        }
    }
}

/// A file the profile writes before launch, relative to the profile directory.
///
/// The profile directory is a sibling of the session projection under
/// `.kin/runs/`, not a child of it: the reconcile scanner walks the projection
/// only, so profile files can never be observed as working-tree changes, and
/// the launched process's working directory is the projection, so they are not
/// entries of the tree the subject agent works in.
#[derive(Debug)]
pub struct ProfileFile {
    pub relative_path: PathBuf,
    pub contents: String,
}

/// Everything `kin with --semantic-only` must apply for one launch.
#[derive(Debug)]
pub struct SemanticOnlyProfile {
    pub files: Vec<ProfileFile>,
    /// Appended to the launch command before the task words, so flags bind to
    /// the CLI rather than to the task text.
    pub extra_args: Vec<OsString>,
    pub tier: EnforcementTier,
    /// One honest line printed at launch describing what is and is not held.
    pub disclosure: String,
}

pub trait AssistantAdapter: Sync {
    /// Canonical assistant id, also the daemon session vendor string.
    fn id(&self) -> &'static str;
    /// Accepted spellings besides the id.
    fn aliases(&self) -> &'static [&'static str];
    /// Binary `kin with` launches. The registry is an allowlist: an arbitrary
    /// program name here would make `kin with` a second `kin exec` with none
    /// of its argument discipline.
    fn program(&self) -> &'static str;
    /// Build the semantic-only profile, or refuse honestly.
    ///
    /// `windows` is a parameter rather than a cfg gate so both arms run in
    /// tests on every host.
    fn semantic_only(&self, profile_dir: &Path, windows: bool) -> Result<SemanticOnlyProfile>;
}

struct ClaudeAdapter;
struct CodexAdapter;
struct GeminiAdapter;

/// Native tools a semantic-only Claude session must not have.
///
/// The profile launches Claude Code with `--tools ""`, which removes the whole
/// built-in set, so none of these exists in the session: no shell, no file
/// reader and no file editor. They are also denied by name in the settings, a
/// second layer that holds if a Claude Code build ever loaded a built-in the
/// flag did not remove. Code is read and changed through Kin's MCP tools, by
/// entity.
const CLAUDE_DENIED_TOOLS: [&str; 11] = [
    "Bash",
    "BashOutput",
    "KillShell",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "Grep",
    "Glob",
    "WebFetch",
];

/// Tool names the semantic-only `PreToolUse` hook adjudicates: all of them.
///
/// The session is meant to hold Kin's MCP tools and nothing else, so the guard
/// sees every call and admits only those. [`semantic_only_guard_verdict`]
/// decides on the tool name it is actually handed rather than trusting the
/// matcher to have selected precisely.
const CLAUDE_HOOK_MATCHER: &str = "*";

/// MCP tools that stay available: Kin's own semantic surface, which is what a
/// semantic-only session is being pointed at.
const CLAUDE_ALLOWED_MCP_PREFIX: &str = "mcp__kin__";

const CLAUDE_SETTINGS_FILE: &str = "semantic-only-settings.json";

/// The MCP configuration the session loads in place of the user's own: Kin's
/// server and no other, so another server's file tools are never available.
const CLAUDE_MCP_CONFIG_FILE: &str = "semantic-only-mcp.json";

/// The tool profile the session's Kin server serves: the agent surface, which
/// includes the entity edits.
const CLAUDE_KIN_TOOL_PROFILE: &str = "agent-default";

/// The largest `PreToolUse` payload the guard will read before refusing.
const MAX_GUARD_PAYLOAD_BYTES: u64 = 4 * 1024 * 1024;

/// What a semantic-only session points an assistant at instead.
fn semantic_only_redirect() -> String {
    "use Kin's MCP tools (semantic_locate, semantic_search, get_context_pack, \
     trace_data_flow, find_references) to discover and read code, kin_mutate on entity ids \
     to change it, and kin_session_exec to build, test and run it; this session has no \
     shell and no file tools"
        .to_string()
}

/// Decide one Claude Code `PreToolUse` payload.
///
/// Admits Kin's MCP tools and nothing else. Fails closed on everything it
/// cannot read: an unparseable payload or a missing tool name refuses. A guard
/// that allowed what it did not understand would be an audit of the payloads
/// that happen to be well formed.
pub fn semantic_only_guard_verdict(payload: &[u8]) -> std::result::Result<(), String> {
    let refuse_unreadable = |detail: &str| {
        Err(format!(
            "semantic-only session: refusing this call because its hook payload {detail}; {}",
            semantic_only_redirect()
        ))
    };

    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return refuse_unreadable("is not readable JSON");
    };
    let Some(tool) = payload.get("tool_name").and_then(serde_json::Value::as_str) else {
        return refuse_unreadable("names no tool");
    };
    if tool.starts_with(CLAUDE_ALLOWED_MCP_PREFIX) {
        return Ok(());
    }
    Err(format!(
        "semantic-only session: refusing '{tool}'; {}",
        semantic_only_redirect()
    ))
}

/// `kin semantic-only-guard` — adjudicate one `PreToolUse` call on stdin.
///
/// Exit 2 is Claude Code's blocking refusal and routes stderr back to the
/// model, which is why the refusal text is written to name a replacement.
pub fn run_semantic_only_guard() -> Result<()> {
    use std::io::Read as _;

    let mut payload = Vec::new();
    // Returning the IO error would exit 1, and every hook exit code except 2 is
    // a non-blocking error that lets the tool run. A guard that cannot read its
    // own input has to refuse explicitly, or failing to read is how a call gets
    // through.
    if let Err(error) = std::io::stdin()
        .lock()
        .take(MAX_GUARD_PAYLOAD_BYTES)
        .read_to_end(&mut payload)
    {
        eprintln!(
            "semantic-only session: refusing this call because its hook payload could not be \
             read ({error}); {}",
            semantic_only_redirect()
        );
        std::process::exit(2);
    }
    if let Err(refusal) = semantic_only_guard_verdict(&payload) {
        eprintln!("{refusal}");
        std::process::exit(2);
    }
    Ok(())
}

/// The `kin` binary the launched assistant calls back into for every guarded
/// tool call.
///
/// Resolved from the running executable rather than left to the assistant's
/// `PATH`: a hook command that cannot be executed is reported by Claude Code as
/// a non-blocking error and the tool then runs, so an unresolvable guard would
/// silently turn enforcement off.
fn guard_program() -> Result<PathBuf> {
    std::env::current_exe().context("resolve the kin executable for the semantic-only guard")
}

/// Turn any guard failure into Claude Code's blocking exit code.
///
/// Exit 2 is the only hook status that blocks; every other non-zero status is
/// reported as a non-blocking error and the tool then runs. So a guard that has
/// been deleted, made non-executable, or is unavailable for a reason nobody
/// enumerated hands the session its full toolset back while the launch banner
/// still advertises the enforced tier — enforcement degrades and nothing says
/// so. Re-raising every failure as 2 makes an unusable guard a refusal instead
/// of an opening, and it covers the whole class rather than the routes someone
/// thought to list.
///
/// It cannot cover a guard replaced by a working program that exits 0. That one
/// answers, and it answers yes, which is why the session is given no tool that
/// can write a file: with every built-in removed and only Kin's MCP server
/// loaded, nothing in the session can reach the guard's path.
///
/// `||` and `exit` mean the same thing to `cmd.exe` as to a POSIX shell, so one
/// spelling serves both arms.
const HOOK_FAIL_CLOSED_SUFFIX: &str = " || exit 2";

/// The shell string Claude Code runs for every guarded tool call.
fn semantic_only_hook_command(program: &Path, windows: bool) -> String {
    format!(
        "{} semantic-only-guard{HOOK_FAIL_CLOSED_SUFFIX}",
        shell_quote_program(program, windows)
    )
}

/// Quote one program path for the shell Claude Code runs a hook command in.
///
/// Hook commands are shell strings, so an unquoted repository path containing a
/// space would split into a program and an argument. POSIX single quotes are
/// exact and expand nothing; the Windows arm uses double quotes, which both
/// `cmd.exe` and a POSIX shell honor, because which of the two runs there is
/// Claude Code's choice and a Windows path cannot contain `"`.
fn shell_quote_program(program: &Path, windows: bool) -> String {
    let program = program.display().to_string();
    if windows {
        return format!("\"{program}\"");
    }
    format!("'{}'", program.replace('\'', r"'\''"))
}

impl AssistantAdapter for ClaudeAdapter {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["claude-code"]
    }

    fn program(&self) -> &'static str {
        "claude"
    }

    fn semantic_only(&self, profile_dir: &Path, windows: bool) -> Result<SemanticOnlyProfile> {
        let deny: Vec<String> = CLAUDE_DENIED_TOOLS.iter().map(|t| t.to_string()).collect();

        // The guard is this binary, not a script inside the profile, so the
        // session holds no off switch for its own enforcement. The same binary
        // serves the session's Kin tools.
        let program = guard_program()?;
        let guard = semantic_only_hook_command(&program, windows);
        let settings = serde_json::json!({
            "permissions": { "deny": deny },
            "hooks": {
                "PreToolUse": [{
                    "matcher": CLAUDE_HOOK_MATCHER,
                    "hooks": [{ "type": "command", "command": guard }]
                }]
            }
        });
        let mcp = serde_json::json!({
            "mcpServers": {
                "kin": {
                    "command": program.display().to_string(),
                    "args": ["mcp", "start", "--tool-profile", CLAUDE_KIN_TOOL_PROFILE]
                }
            }
        });

        Ok(SemanticOnlyProfile {
            // `--tools` and `--mcp-config` each take a list, so each is
            // followed by another flag that ends it. The task words that come
            // after `--settings` can then never be read as tool names or as MCP
            // configurations.
            extra_args: vec![
                OsString::from("--tools"),
                OsString::from(""),
                OsString::from("--mcp-config"),
                profile_dir.join(CLAUDE_MCP_CONFIG_FILE).into_os_string(),
                OsString::from("--strict-mcp-config"),
                OsString::from("--settings"),
                profile_dir.join(CLAUDE_SETTINGS_FILE).into_os_string(),
            ],
            files: vec![
                ProfileFile {
                    relative_path: PathBuf::from(CLAUDE_SETTINGS_FILE),
                    contents: serde_json::to_string_pretty(&settings)?,
                },
                ProfileFile {
                    relative_path: PathBuf::from(CLAUDE_MCP_CONFIG_FILE),
                    contents: serde_json::to_string_pretty(&mcp)?,
                },
            ],
            tier: EnforcementTier::Enforced,
            disclosure: "semantic-only [enforced]: every Claude Code built-in tool is removed \
                 (--tools \"\"), including Bash, Read, Edit and Write, and only Kin's MCP server \
                 is loaded (--strict-mcp-config); a hook refuses any other tool call. Code is read \
                 and changed through Kin's tools, by entity. Build and test verification runs \
                 outside this session, for example with `kin exec -- <command>`."
                .to_string(),
        })
    }
}

impl AssistantAdapter for CodexAdapter {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    fn program(&self) -> &'static str {
        "codex"
    }

    fn semantic_only(&self, _profile_dir: &Path, _windows: bool) -> Result<SemanticOnlyProfile> {
        bail!(
            "--semantic-only is enforced for claude only today; codex has no capability layer \
             wired yet, and shipping guidance as if it were enforcement would overclaim the flag"
        );
    }
}

impl AssistantAdapter for GeminiAdapter {
    fn id(&self) -> &'static str {
        "gemini"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["gemini-cli"]
    }

    fn program(&self) -> &'static str {
        "gemini"
    }

    fn semantic_only(&self, _profile_dir: &Path, _windows: bool) -> Result<SemanticOnlyProfile> {
        bail!(
            "--semantic-only is enforced for claude only today; gemini has no capability layer \
             wired yet, and shipping guidance as if it were enforcement would overclaim the flag"
        );
    }
}

static ADAPTERS: [&dyn AssistantAdapter; 3] = [&ClaudeAdapter, &CodexAdapter, &GeminiAdapter];

/// Resolve an assistant spelling to its adapter.
pub fn adapter_for(assistant: &str) -> Result<&'static dyn AssistantAdapter> {
    let wanted = assistant.trim().to_ascii_lowercase();
    for adapter in ADAPTERS {
        if adapter.id() == wanted || adapter.aliases().contains(&wanted.as_str()) {
            return Ok(adapter);
        }
    }
    let known = ADAPTERS
        .iter()
        .map(|a| a.id())
        .collect::<Vec<_>>()
        .join(", ");
    bail!("unknown assistant '{assistant}'; kin with supports: {known}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where a released `kin` sits, for the tests that ask what a session may
    /// do about its own guard.
    const GUARD_PROGRAM: &str = "/usr/local/bin/kin";

    fn payload(tool: &str, command: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": { "command": command }
        }))
        .unwrap()
    }

    fn profile_file(profile: &SemanticOnlyProfile, name: &str) -> serde_json::Value {
        let file = profile
            .files
            .iter()
            .find(|f| f.relative_path == Path::new(name))
            .unwrap_or_else(|| panic!("{name} present"));
        serde_json::from_str(&file.contents).unwrap()
    }

    fn args_of(profile: &SemanticOnlyProfile) -> Vec<String> {
        profile
            .extra_args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// Every way of reading a file that the adversarial review of the original
    /// blocklist enumerated, plus the blocklist's own entries.
    ///
    /// `sed` is the falsifying probe for this whole arm: the previous profile
    /// blocked `grep` by name, so an acceptance written around `grep` passes
    /// while enforcing almost nothing. `sed -n p FILE` reads any file and was
    /// deliberately left allowed, so a guard that refuses `grep` and admits
    /// `sed` is not enforcement.
    const BYPASS_VECTORS: &[&str] = &[
        // Stream editors the previous profile deliberately left allowed.
        "sed -n p src/main.rs",
        "sed '' src/main.rs",
        "awk '{print}' src/main.rs",
        "awk 1 src/main.rs",
        // Nested shells.
        "bash -c 'cat src/main.rs'",
        "sh -c 'cat src/main.rs'",
        "zsh -c 'cat src/main.rs'",
        // Builtins and substitution.
        "echo $(cat src/main.rs)",
        "printf '%s' \"$(<src/main.rs)\"",
        "while IFS= read -r l; do echo \"$l\"; done < src/main.rs",
        "cat<src/main.rs",
        // Interpreters.
        "perl -ne print src/main.rs",
        "perl -0777 -pe '' src/main.rs",
        "python3 -c \"print(open('src/main.rs').read())\"",
        "node -e \"process.stdout.write(require('fs').readFileSync('src/main.rs','utf8'))\"",
        "ruby -e 'puts File.read(\"src/main.rs\")'",
        // Pure readers absent from the blocklist.
        "nl src/main.rs",
        "od -c src/main.rs",
        "xxd src/main.rs",
        "hexdump -C src/main.rs",
        "cut -c1- src/main.rs",
        "paste src/main.rs",
        "sort src/main.rs",
        "uniq src/main.rs",
        "rev src/main.rs",
        "tac src/main.rs",
        "fold src/main.rs",
        "expand src/main.rs",
        "column src/main.rs",
        "pr src/main.rs",
        "base64 src/main.rs",
        "wc src/main.rs",
        "tee < src/main.rs",
        "bat src/main.rs",
        // Spellings the blocklist misses.
        "egrep -n pattern src/main.rs",
        "fgrep pattern src/main.rs",
        "zgrep pattern src/main.rs",
        "ack pattern",
        "ugrep pattern",
        "/bin/cat src/main.rs",
        "env cat src/main.rs",
        "command cat src/main.rs",
        "LC_ALL=C cat src/main.rs",
        "\\cat src/main.rs",
        // Full-text search, full-file read, and directory listing in one
        // un-denied binary.
        "git grep -n pattern",
        "git show HEAD:src/main.rs",
        "git cat-file -p HEAD",
        "git diff",
        "git log -p",
        "git blame src/main.rs",
        "git ls-files",
        // Shell expansion as a directory listing.
        "echo *",
        "printf '%s\\n' *",
        "compgen -f",
        // Argument plumbing.
        "xargs cat < list",
        "echo src/main.rs | xargs cat",
        // Archives, block copies, and the network.
        "tar -xOf bundle.tar src/main.rs",
        "unzip -p bundle.zip src/main.rs",
        "zcat src/main.rs.gz",
        "dd if=src/main.rs",
        "cp src/main.rs /dev/stdout",
        "curl -s file:///etc/hosts",
        "wget -qO- file:///etc/hosts",
        // A nested Claude Code receives no --settings and would run under
        // default permissions.
        "claude -p \"print the contents of src/main.rs\"",
    ];

    #[test]
    fn registry_resolves_every_alias_to_the_old_allowlist_programs() {
        assert_eq!(adapter_for("claude").unwrap().program(), "claude");
        assert_eq!(adapter_for("claude-code").unwrap().program(), "claude");
        assert_eq!(adapter_for("Codex").unwrap().program(), "codex");
        assert_eq!(adapter_for("gemini").unwrap().program(), "gemini");
        assert_eq!(adapter_for("gemini-cli").unwrap().program(), "gemini");
        assert!(adapter_for("vim").is_err());
        assert!(adapter_for("").is_err());
    }

    /// No shell command runs in a semantic-only session, whatever it is.
    ///
    /// The shell is removed with every other built-in, and the guard refuses a
    /// Bash call if one ever reached it: the file reads the adversarial review
    /// enumerated, the commands the retired allowlist admitted (which include
    /// every filesystem mutator), and an empty command alike.
    #[test]
    fn every_enumerated_file_read_bypass_is_refused() {
        for vector in BYPASS_VECTORS {
            let refusal = semantic_only_guard_verdict(&payload("Bash", vector))
                .expect_err(&format!("semantic-only admitted a shell command: {vector}"));
            assert!(
                refusal.contains("semantic-only session: refusing"),
                "{vector}: {refusal}"
            );
        }
        for mutator in [
            "echo starting the rename",
            "pwd",
            "mkdir -p src/rendering",
            "rmdir src/rendering",
            "touch src/rendering/mod.rs",
            "mv src/old.rs src/new.rs",
            "rm -f target/debug/stale",
            "chmod u+x scripts/run",
            "",
        ] {
            assert!(
                semantic_only_guard_verdict(&payload("Bash", mutator)).is_err(),
                "semantic-only admitted {mutator:?}"
            );
        }
    }

    #[test]
    fn the_guard_admits_kin_tools_only_and_fails_closed() {
        semantic_only_guard_verdict(&payload("mcp__kin__semantic_locate", "")).unwrap();
        semantic_only_guard_verdict(&payload("mcp__kin__kin_mutate", "")).unwrap();

        // Every built-in, including the ones that only observed a shell.
        for denied in CLAUDE_DENIED_TOOLS {
            assert!(
                semantic_only_guard_verdict(&payload(denied, "")).is_err(),
                "guard admitted {denied}"
            );
        }
        // Another server's tools, including one whose name starts like Kin's.
        for other in [
            "mcp__filesystem__read_file",
            "mcp__filesystem__write_file",
            "mcp__kinlab__read",
            "mcp__kin_extra__write",
            "Task",
            "Agent",
        ] {
            assert!(
                semantic_only_guard_verdict(&payload(other, "")).is_err(),
                "guard admitted {other}"
            );
        }

        // Anything unreadable is a refusal, not an admission.
        assert!(semantic_only_guard_verdict(b"").is_err());
        assert!(semantic_only_guard_verdict(b"not json").is_err());
        assert!(semantic_only_guard_verdict(br#"{"tool_input":{"command":"pwd"}}"#).is_err());
        assert!(semantic_only_guard_verdict(br#"{"tool_name":7}"#).is_err());
    }

    /// The session has no built-in at all and loads Kin's server alone.
    #[test]
    fn claude_profile_removes_every_builtin_and_loads_only_kin() {
        let dir = Path::new("/tmp/profile");
        let profile = ClaudeAdapter.semantic_only(dir, false).unwrap();
        assert_eq!(profile.tier, EnforcementTier::Enforced);

        let args = args_of(&profile);
        assert_eq!(
            args,
            vec![
                "--tools".to_string(),
                String::new(),
                "--mcp-config".to_string(),
                dir.join(CLAUDE_MCP_CONFIG_FILE).display().to_string(),
                "--strict-mcp-config".to_string(),
                "--settings".to_string(),
                dir.join(CLAUDE_SETTINGS_FILE).display().to_string(),
            ]
        );
        // Both list-valued flags are ended by the flag after their value, and
        // the last flag takes one value, so a task word can bind to neither.
        assert!(args[2].starts_with("--") && args[4].starts_with("--"));
        assert_eq!(args[5], "--settings");

        let settings = profile_file(&profile, CLAUDE_SETTINGS_FILE);
        let deny: Vec<String> = settings["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        for tool in CLAUDE_DENIED_TOOLS {
            assert!(deny.contains(&tool.to_string()), "missing {tool}");
        }
        assert!(deny.iter().all(|rule| !rule.starts_with("mcp__kin__")));

        let hook = &settings["hooks"]["PreToolUse"][0];
        assert_eq!(hook["matcher"], "*", "the guard must see every call");
        let command = hook["hooks"][0]["command"].as_str().unwrap();
        assert!(command.contains(" semantic-only-guard"), "{command}");
        assert!(command.starts_with('\''), "{command}");

        let mcp = profile_file(&profile, CLAUDE_MCP_CONFIG_FILE);
        let servers = mcp["mcpServers"].as_object().unwrap();
        assert_eq!(servers.keys().collect::<Vec<_>>(), vec!["kin"]);
        assert_eq!(
            servers["kin"]["command"],
            guard_program().unwrap().display().to_string()
        );
        assert_eq!(
            servers["kin"]["args"],
            serde_json::json!(["mcp", "start", "--tool-profile", "agent-default"])
        );
        assert!(
            profile
                .files
                .iter()
                .all(|f| f.relative_path != Path::new("deny-discovery.sh")),
            "the guard must not be a script the session can delete or rewrite"
        );
    }

    /// The printed line is the operator's only description of what a
    /// semantic-only launch holds, so it is asserted against what the profile
    /// actually does, and it must not promise work the session cannot do.
    #[test]
    fn the_disclosure_describes_exactly_what_is_enforced() {
        for windows in [false, true] {
            let profile = ClaudeAdapter
                .semantic_only(Path::new("/tmp/profile"), windows)
                .unwrap();
            let disclosure = &profile.disclosure;
            let args = args_of(&profile);

            assert!(disclosure.contains("[enforced]"), "{disclosure}");
            assert!(
                disclosure.contains("--tools \"\"") && args[0] == "--tools" && args[1].is_empty()
            );
            assert!(
                disclosure.contains("--strict-mcp-config")
                    && args.contains(&"--strict-mcp-config".to_string())
            );
            for named in ["Bash", "Read", "Edit", "Write"] {
                assert!(disclosure.contains(named), "{named} unnamed: {disclosure}");
                assert!(CLAUDE_DENIED_TOOLS.contains(&named));
            }
            assert!(disclosure.contains("outside this session"), "{disclosure}");
            for retired in ["Bash is refused unless", "mkdir", "rm,", "chmod"] {
                assert!(
                    !disclosure.contains(retired),
                    "the disclosure still describes a shell: {disclosure}"
                );
            }
        }
    }

    /// Both platform arms carry the guard and the same boundary.
    #[test]
    fn both_platform_arms_install_the_same_guard() {
        let unix = ClaudeAdapter
            .semantic_only(Path::new("/tmp/profile"), false)
            .unwrap();
        let windows = ClaudeAdapter
            .semantic_only(Path::new("/tmp/profile"), true)
            .unwrap();

        for profile in [&unix, &windows] {
            assert_eq!(profile.tier, EnforcementTier::Enforced);
            assert_eq!(profile.files.len(), 2);
            let settings = profile_file(profile, CLAUDE_SETTINGS_FILE);
            assert_eq!(
                settings["hooks"]["PreToolUse"][0]["matcher"],
                CLAUDE_HOOK_MATCHER
            );
        }
        assert_eq!(unix.disclosure, windows.disclosure);
        assert_eq!(args_of(&unix), args_of(&windows));

        let quoted = shell_quote_program(Path::new("/opt/kin tools/kin"), false);
        assert_eq!(quoted, "'/opt/kin tools/kin'");
        assert_eq!(
            shell_quote_program(Path::new("/opt/it's/kin"), false),
            r"'/opt/it'\''s/kin'"
        );
        assert_eq!(
            shell_quote_program(Path::new(r"C:\Program Files\kin.exe"), true),
            "\"C:\\Program Files\\kin.exe\""
        );
    }

    /// Enforcement must not be able to leave without the session noticing.
    ///
    /// Claude Code reports a `PreToolUse` hook it cannot execute as a
    /// non-blocking error and then runs the tool, so a guard that is deleted or
    /// made non-executable must still block.
    #[test]
    fn the_hook_command_turns_an_unusable_guard_into_a_refusal() {
        // Asserted against the literal exit code Claude Code treats as blocking,
        // never against `HOOK_FAIL_CLOSED_SUFFIX`, so emptying the constant
        // cannot leave this green.
        for windows in [false, true] {
            let command = semantic_only_hook_command(Path::new(GUARD_PROGRAM), windows);
            assert!(
                command.ends_with(" || exit 2"),
                "a guard that cannot run must block, not warn: {command}"
            );
            assert!(command.contains(" semantic-only-guard"), "{command}");

            let profile = ClaudeAdapter
                .semantic_only(Path::new("/tmp/profile"), windows)
                .unwrap();
            let installed = profile_file(&profile, CLAUDE_SETTINGS_FILE)["hooks"]["PreToolUse"][0]
                ["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .to_string();
            assert!(installed.ends_with(" || exit 2"), "{installed}");
        }
    }

    /// Run the hook string the way Claude Code runs it and read the status.
    ///
    /// The assertion above is on the text; this one is on the behavior, which is
    /// what the profile actually depends on. It runs only where a POSIX shell
    /// exists, and it asks the same question as the text assertion rather than a
    /// weaker one: a missing guard must exit 2, because 2 is the only status
    /// Claude Code blocks on.
    #[cfg(unix)]
    #[test]
    fn a_missing_guard_exits_with_the_blocking_status_in_a_real_shell() {
        use std::process::{Command, Stdio};

        let missing = Path::new("/nonexistent/kin directory/kin");
        let status = Command::new("sh")
            .arg("-c")
            .arg(semantic_only_hook_command(missing, false))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run the hook command");
        assert_eq!(
            status.code(),
            Some(2),
            "an unrunnable guard must exit 2; every other status lets the tool run"
        );

        // The falsification: the bare command this replaced exits 127, which
        // Claude Code reports as a non-blocking error and then runs the tool.
        let bare = format!(
            "{} semantic-only-guard",
            shell_quote_program(missing, false)
        );
        let bare_status = Command::new("sh")
            .arg("-c")
            .arg(bare)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run the bare command");
        assert_ne!(
            bare_status.code(),
            Some(2),
            "the bare command must not already block, or this test proves nothing"
        );
    }

    /// A subject may not disarm the guard adjudicating it.
    ///
    /// A guard replaced by a program that exits 0 answers yes to everything, and
    /// the fail-closed suffix cannot catch that. What holds it is that the
    /// session has no tool that can touch the guard's path: no shell, no file
    /// writer, and no MCP server but Kin's.
    #[test]
    fn a_session_cannot_reach_the_guard_that_enforces_it() {
        for reach in [
            "rm /usr/local/bin/kin",
            "mv /usr/local/bin/kin /tmp/parked",
            "mv scratch/passthrough /usr/local/bin/kin",
            "chmod 000 /usr/local/bin/kin",
            "rm -r /usr/local/bin",
        ] {
            assert!(
                semantic_only_guard_verdict(&payload("Bash", reach)).is_err(),
                "semantic-only admitted a disarm: {reach}"
            );
        }
        for writer in ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"] {
            assert!(CLAUDE_DENIED_TOOLS.contains(&writer), "{writer} not denied");
            assert!(semantic_only_guard_verdict(&payload(writer, "")).is_err());
        }
        let profile = ClaudeAdapter
            .semantic_only(Path::new("/tmp/profile"), false)
            .unwrap();
        let args = args_of(&profile);
        assert_eq!((args[0].as_str(), args[1].as_str()), ("--tools", ""));
        assert!(args.contains(&"--strict-mcp-config".to_string()));
    }

    #[test]
    fn codex_and_gemini_fail_closed_instead_of_overclaiming() {
        for name in ["codex", "gemini"] {
            let err = adapter_for(name)
                .unwrap()
                .semantic_only(Path::new("/tmp/profile"), false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("claude only"), "{name}: {err}");
        }
    }
}
