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

/// Native tools Claude Code must refuse in a semantic-only session.
const CLAUDE_DENIED_TOOLS: [&str; 3] = ["Grep", "Glob", "Read"];

/// File-reading commands denied outright through Claude Code's own permission
/// engine.
///
/// This list is not the boundary — [`semantic_only_bash_verdict`] is, and it
/// refuses every command it cannot name. These rules are the second layer:
/// a `PreToolUse` hook that cannot be executed is reported as a non-blocking
/// error and the tool runs anyway, so the most common readers are also denied
/// by a mechanism that needs no subprocess.
const CLAUDE_DENIED_BASH_READERS: [&str; 13] = [
    "grep", "rg", "ag", "find", "fd", "cat", "head", "tail", "less", "more", "tree", "strings",
    "ls",
];

/// Bash commands a semantic-only Claude session may run.
///
/// This is an allowlist, and the inversion is the point. A blocklist over a
/// shell cannot be finished: `sed`, `awk`, `perl`, `python3`, `node`, `ruby`,
/// `git show`, `od`, `base64`, `curl file://`, and a nested `claude -p` all
/// put file contents on stdout, and every blocked spelling has an unblocked
/// one (`egrep`, `/bin/cat`, `env cat`). A command this session cannot name is
/// refused, so an unlisted reader is refused by default rather than by
/// enumeration.
///
/// Membership rule: the command must emit a literal, report the working
/// directory, or mutate the filesystem in a way `Edit` and `Write` cannot
/// express. Nothing here can put the contents of a file it did not receive
/// onto stdout.
const CLAUDE_ALLOWED_BASH: [&str; 11] = [
    "echo", "printf", "pwd", "true", "false", "mkdir", "rmdir", "touch", "mv", "rm", "chmod",
];

/// Path roots an allowed command may not name.
///
/// `mv src/a /dev/stdout` is a file read spelled as a move, and `/proc/self/*`
/// re-exposes the launched process's own argv and environment. Neither needs a
/// disallowed command, so the allowlist alone does not hold them.
const CLAUDE_REFUSED_PATH_ROOTS: [&str; 3] = ["/dev/", "/proc/", "/sys/"];

/// Tool names the semantic-only `PreToolUse` hook is asked to adjudicate.
///
/// Written in the documented matcher style — an unanchored alternation of tool
/// names, plus the `mcp__.*` prefix form — rather than as an anchored regex,
/// because the matcher's exact anchoring semantics are Claude Code's to define.
/// [`semantic_only_guard_verdict`] therefore re-decides on the tool name it is
/// actually handed instead of trusting the matcher to have selected precisely.
const CLAUDE_HOOK_MATCHER: &str = "Bash|Grep|Glob|Read|mcp__.*";

/// MCP tools that stay available: Kin's own semantic surface, which is what a
/// semantic-only session is being pointed at.
const CLAUDE_ALLOWED_MCP_PREFIX: &str = "mcp__kin__";

/// Tools that only observe or end an already-adjudicated Bash call. The command
/// they refer to passed [`semantic_only_bash_verdict`] before it ran, so its
/// output cannot carry a file the session may not read.
const CLAUDE_ALLOWED_BASH_FOLLOWUPS: [&str; 2] = ["BashOutput", "KillShell"];

const CLAUDE_SETTINGS_FILE: &str = "semantic-only-settings.json";

/// The largest `PreToolUse` payload the guard will read before refusing.
const MAX_GUARD_PAYLOAD_BYTES: u64 = 4 * 1024 * 1024;

/// Whether one character may appear in a semantic-only Bash command.
///
/// This is the second allowlist, and it exists because prefix matching alone
/// decides nothing on a shell: `echo $(cat f)`, `printf '%s' "$(<f)"`,
/// `while read l; do echo "$l"; done < f`, `echo *`, and `mkdir x; cat f` all
/// begin with a command that is allowed and end in a file read. Command
/// substitution, redirection, pipes, sequencing, globbing, and escapes are
/// spelled with characters, so refusing the characters refuses the whole class
/// rather than the instances of it someone thought to list.
fn is_allowed_bash_char(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            ' ' | '-' | '_' | '.' | '/' | '=' | ':' | ',' | '+' | '%' | '\'' | '"'
        )
}

/// What a semantic-only session points an assistant at instead.
fn semantic_only_redirect() -> String {
    format!(
        "use Kin's MCP tools (semantic_locate, semantic_search, get_context_pack, \
         trace_data_flow, find_references) to discover and read code, and Edit/Write to \
         change it; Bash accepts only: {}",
        CLAUDE_ALLOWED_BASH.join(", ")
    )
}

/// Decide whether a semantic-only session may run one Bash command.
///
/// `Err` carries the line the assistant is shown, so a refusal teaches the
/// replacement rather than only naming the rule.
pub fn semantic_only_bash_verdict(command: &str) -> std::result::Result<(), String> {
    let command = command.trim();
    if command.is_empty() {
        return Err(format!(
            "semantic-only session: refusing an empty Bash command; {}",
            semantic_only_redirect()
        ));
    }
    if let Some(character) = command.chars().find(|c| !is_allowed_bash_char(*c)) {
        return Err(format!(
            "semantic-only session: refusing this Bash command because it contains {character:?}. \
             Command substitution, redirection, pipes, sequencing, globbing, and escapes are \
             refused because they turn an allowed command into a file read; {}",
            semantic_only_redirect()
        ));
    }
    let program = command.split(' ').next().unwrap_or_default();
    if !CLAUDE_ALLOWED_BASH.contains(&program) {
        return Err(format!(
            "semantic-only session: refusing Bash command '{program}'. This session refuses every \
             command it cannot name, because a list of blocked readers can always be spelled \
             around; {}",
            semantic_only_redirect()
        ));
    }
    if let Some(root) = CLAUDE_REFUSED_PATH_ROOTS
        .iter()
        .find(|root| command.contains(**root))
    {
        return Err(format!(
            "semantic-only session: refusing this Bash command because it names {root}, which \
             turns an allowed command into a file read; {}",
            semantic_only_redirect()
        ));
    }
    Ok(())
}

/// Decide one Claude Code `PreToolUse` payload.
///
/// Fails closed on everything it cannot read: an unparseable payload, a missing
/// tool name, a `Bash` call with no command string, and any tool the matcher
/// selected that this function was not written to allow all refuse. A guard
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

    if tool == "Bash" {
        let Some(command) = payload
            .get("tool_input")
            .and_then(|input| input.get("command"))
            .and_then(serde_json::Value::as_str)
        else {
            return refuse_unreadable("is a Bash call carrying no command string");
        };
        return semantic_only_bash_verdict(command);
    }
    if tool.starts_with(CLAUDE_ALLOWED_MCP_PREFIX) || CLAUDE_ALLOWED_BASH_FOLLOWUPS.contains(&tool)
    {
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
        let mut deny: Vec<String> = CLAUDE_DENIED_TOOLS.iter().map(|t| t.to_string()).collect();
        deny.extend(
            CLAUDE_DENIED_BASH_READERS
                .iter()
                .map(|c| format!("Bash({c}:*)")),
        );

        // The guard is this binary, not a script inside the profile. That is
        // what makes the profile non-disarmable: `Edit`, `Write`, and `rm` stay
        // available by design, so a hook script the session could delete or
        // rewrite would be enforcement the subject holds the off switch for.
        let guard = format!(
            "{} semantic-only-guard",
            shell_quote_program(&guard_program()?, windows)
        );
        let settings = serde_json::json!({
            "permissions": { "deny": deny },
            "hooks": {
                "PreToolUse": [{
                    "matcher": CLAUDE_HOOK_MATCHER,
                    "hooks": [{ "type": "command", "command": guard }]
                }]
            }
        });

        Ok(SemanticOnlyProfile {
            extra_args: vec![
                OsString::from("--settings"),
                profile_dir.join(CLAUDE_SETTINGS_FILE).into_os_string(),
            ],
            files: vec![ProfileFile {
                relative_path: PathBuf::from(CLAUDE_SETTINGS_FILE),
                contents: serde_json::to_string_pretty(&settings)?,
            }],
            tier: EnforcementTier::Enforced,
            disclosure: format!(
                "semantic-only [enforced]: Grep/Glob/Read are refused; Bash is refused unless the \
                 command is one of {}; MCP tools other than Kin's are refused. Kin's MCP tools, \
                 Edit, and Write stay available.",
                CLAUDE_ALLOWED_BASH.join(", ")
            ),
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

    #[test]
    fn every_enumerated_file_read_bypass_is_refused() {
        for vector in BYPASS_VECTORS {
            let refusal = semantic_only_bash_verdict(vector)
                .expect_err(&format!("semantic-only admitted a file read: {vector}"));
            assert!(
                refusal.contains("semantic-only session: refusing"),
                "{vector}: {refusal}"
            );
        }
        // The commands the old blocklist did name must still be refused, so
        // inverting the list did not trade one gap for another.
        for reader in CLAUDE_DENIED_BASH_READERS {
            let command = format!("{reader} src/main.rs");
            assert!(
                semantic_only_bash_verdict(&command).is_err(),
                "semantic-only admitted {command}"
            );
        }
    }

    #[test]
    fn the_allowlisted_commands_are_the_ones_that_run() {
        for allowed in [
            "echo starting the rename",
            "printf ready",
            "pwd",
            "true",
            "false",
            "mkdir -p src/rendering",
            "rmdir src/rendering",
            "touch src/rendering/mod.rs",
            "mv src/old.rs src/new.rs",
            "rm -f target/debug/stale",
            "chmod u+x scripts/run",
        ] {
            semantic_only_bash_verdict(allowed).unwrap_or_else(|refusal| {
                panic!("semantic-only refused a permitted command {allowed}: {refusal}")
            });
        }

        // An allowed command still cannot name a path whose read is the point.
        for disclosure in [
            "mv src/main.rs /dev/stdout",
            "echo /proc/self/environ",
            "rm /sys/kernel/notes",
        ] {
            assert!(
                semantic_only_bash_verdict(disclosure).is_err(),
                "semantic-only admitted {disclosure}"
            );
        }

        assert!(semantic_only_bash_verdict("").is_err());
        assert!(semantic_only_bash_verdict("   ").is_err());
    }

    #[test]
    fn the_guard_reads_bash_commands_out_of_the_hook_payload_and_fails_closed() {
        let payload = |tool: &str, command: &str| {
            serde_json::to_vec(&serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": { "command": command }
            }))
            .unwrap()
        };

        semantic_only_guard_verdict(&payload("Bash", "mkdir -p src/rendering")).unwrap();
        assert!(semantic_only_guard_verdict(&payload("Bash", "sed -n p src/main.rs")).is_err());

        // The hook is also a backstop for the tools the deny rules name, so a
        // deny rule that failed to apply is still refused here.
        for denied in CLAUDE_DENIED_TOOLS {
            assert!(
                semantic_only_guard_verdict(&payload(denied, "")).is_err(),
                "guard admitted {denied}"
            );
        }

        // Kin's MCP surface is what the session is pointed at; another
        // server's file reader is not.
        semantic_only_guard_verdict(&payload("mcp__kin__semantic_locate", "")).unwrap();
        semantic_only_guard_verdict(&payload("BashOutput", "")).unwrap();
        assert!(semantic_only_guard_verdict(&payload("mcp__filesystem__read_file", "")).is_err());
        assert!(semantic_only_guard_verdict(&payload("mcp__kinlab__read", "")).is_err());

        // Anything unreadable is a refusal, not an admission.
        assert!(semantic_only_guard_verdict(b"").is_err());
        assert!(semantic_only_guard_verdict(b"not json").is_err());
        assert!(semantic_only_guard_verdict(br#"{"tool_input":{"command":"pwd"}}"#).is_err());
        assert!(semantic_only_guard_verdict(br#"{"tool_name":"Bash"}"#).is_err());
        assert!(
            semantic_only_guard_verdict(br#"{"tool_name":"Bash","tool_input":{"command":7}}"#)
                .is_err()
        );
    }

    #[test]
    fn claude_profile_denies_discovery_and_keeps_the_edit_path() {
        let dir = Path::new("/tmp/profile");
        let profile = ClaudeAdapter.semantic_only(dir, false).unwrap();
        assert_eq!(profile.tier, EnforcementTier::Enforced);

        let settings = profile
            .files
            .iter()
            .find(|f| f.relative_path == Path::new(CLAUDE_SETTINGS_FILE))
            .expect("settings file present");
        let parsed: serde_json::Value = serde_json::from_str(&settings.contents).unwrap();
        let deny: Vec<String> = parsed["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        for tool in CLAUDE_DENIED_TOOLS {
            assert!(deny.contains(&tool.to_string()), "missing {tool}");
        }
        for reader in CLAUDE_DENIED_BASH_READERS {
            assert!(
                deny.contains(&format!("Bash({reader}:*)")),
                "missing {reader}"
            );
        }
        for kept in ["Edit", "Write", "Bash", "mcp__kin__semantic_locate"] {
            assert!(!deny.contains(&kept.to_string()), "overdenies {kept}");
        }

        // The hook must be aimed at Bash. Aimed at the denied tool names alone
        // it would guard a door the deny rules already hold and cover none of
        // the surface every bypass in `BYPASS_VECTORS` runs through.
        let hook = &parsed["hooks"]["PreToolUse"][0];
        assert_eq!(hook["matcher"], CLAUDE_HOOK_MATCHER);
        assert!(
            hook["matcher"].as_str().unwrap().contains("Bash"),
            "the hook must see Bash"
        );
        let command = hook["hooks"][0]["command"].as_str().unwrap();
        assert!(
            command.ends_with(" semantic-only-guard"),
            "the hook must call the guard: {command}"
        );
        assert!(
            command.starts_with('\''),
            "the guard program must be quoted for the hook shell: {command}"
        );
        assert!(
            profile
                .files
                .iter()
                .all(|f| f.relative_path != Path::new("deny-discovery.sh")),
            "the guard must not be a script the session can delete or rewrite"
        );

        let args: Vec<String> = profile
            .extra_args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "--settings");
        assert!(args[1].ends_with(CLAUDE_SETTINGS_FILE));
    }

    /// The printed line is the operator's only description of what a
    /// semantic-only launch holds, so it is asserted against the sets it
    /// describes rather than against a copy of its own words.
    #[test]
    fn the_disclosure_describes_exactly_what_is_enforced() {
        for windows in [false, true] {
            let profile = ClaudeAdapter
                .semantic_only(Path::new("/tmp/profile"), windows)
                .unwrap();
            let disclosure = &profile.disclosure;

            assert!(disclosure.contains("[enforced]"), "{disclosure}");
            for tool in CLAUDE_DENIED_TOOLS {
                assert!(disclosure.contains(tool), "{tool} unnamed: {disclosure}");
            }
            for allowed in CLAUDE_ALLOWED_BASH {
                assert!(
                    disclosure.contains(allowed),
                    "{allowed} unnamed: {disclosure}"
                );
                semantic_only_bash_verdict(allowed).unwrap_or_else(|refusal| {
                    panic!("the disclosure names {allowed} but the guard refuses it: {refusal}")
                });
            }
            // The claim the review falsified: the old line said file-reading
            // Bash was refused while thirteen prefixes were. The line must not
            // describe the Bash boundary as anything but the allowlist.
            assert!(
                disclosure.contains("Bash is refused unless"),
                "{disclosure}"
            );
            assert!(
                !disclosure.contains("backstop"),
                "the disclosure must not credit coverage to a backstop: {disclosure}"
            );
            assert!(disclosure.contains("MCP tools other than Kin's are refused"));
        }
    }

    /// Both platform arms carry the guard.
    ///
    /// The guard is the `kin` binary, so nothing about it needs a POSIX shell
    /// script or an executable bit — which is what previously left the Windows
    /// arm with deny rules and no hook at all.
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
            assert_eq!(profile.files.len(), 1);
            let parsed: serde_json::Value =
                serde_json::from_str(&profile.files[0].contents).unwrap();
            assert_eq!(
                parsed["hooks"]["PreToolUse"][0]["matcher"],
                CLAUDE_HOOK_MATCHER
            );
        }
        assert_eq!(unix.disclosure, windows.disclosure);

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
