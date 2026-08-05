// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One adapter per assistant CLI, in a registry.
//!
//! The adapter owns the full per-CLI contract: launch program, alias set, and
//! the `--semantic-only` capability profile with a self-declared enforcement
//! tier. `kin setup`'s registration writers and `kin with`'s launcher resolve
//! assistants through this same registry, so a client cannot be registerable
//! but not launchable, or instructed but not registered.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

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
/// The profile directory lives in session metadata, beside the projection
/// root rather than inside it, so profile files never enter the reconciled
/// delta.
#[derive(Debug)]
pub struct ProfileFile {
    pub relative_path: PathBuf,
    pub contents: String,
    pub executable: bool,
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

/// File-reading commands denied through Bash. Pure readers only: dual-use
/// stream editors stay allowed so the preserved edit path keeps working, and
/// the PreToolUse backstop still covers the named discovery tools.
const CLAUDE_DENIED_BASH_READERS: [&str; 13] = [
    "grep", "rg", "ag", "find", "fd", "cat", "head", "tail", "less", "more", "tree", "strings",
    "ls",
];

const CLAUDE_HOOK_SCRIPT: &str = "deny-discovery.sh";
const CLAUDE_SETTINGS_FILE: &str = "semantic-only-settings.json";

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

        let mut settings = serde_json::json!({
            "permissions": { "deny": deny }
        });

        let mut files = Vec::new();
        // The hook is a deterministic backstop behind the deny rules: exit 2
        // refuses the call and the stderr line reaches the model. It is a
        // POSIX shell script, so it only exists on non-Windows launches; the
        // deny rules above enforce on every platform.
        if !windows {
            let hook_path = profile_dir.join(CLAUDE_HOOK_SCRIPT);
            settings["hooks"] = serde_json::json!({
                "PreToolUse": [{
                    "matcher": "Grep|Glob|Read",
                    "hooks": [{
                        "type": "command",
                        "command": hook_path.display().to_string(),
                    }]
                }]
            });
            files.push(ProfileFile {
                relative_path: PathBuf::from(CLAUDE_HOOK_SCRIPT),
                contents: "#!/bin/sh\n\
                           echo \"semantic-only session: native discovery is disabled; use Kin's \
                           MCP tools (semantic_locate, get_context_pack, trace_data_flow)\" >&2\n\
                           exit 2\n"
                    .to_string(),
                executable: true,
            });
        }

        files.push(ProfileFile {
            relative_path: PathBuf::from(CLAUDE_SETTINGS_FILE),
            contents: serde_json::to_string_pretty(&settings)?,
            executable: false,
        });

        let backstop = if windows {
            "deny rules only, no hook backstop on Windows"
        } else {
            "deny rules plus PreToolUse backstop"
        };
        Ok(SemanticOnlyProfile {
            extra_args: vec![
                OsString::from("--settings"),
                profile_dir.join(CLAUDE_SETTINGS_FILE).into_os_string(),
            ],
            files,
            tier: EnforcementTier::Enforced,
            disclosure: format!(
                "semantic-only [enforced]: Grep/Glob/Read and file-reading Bash are refused \
                 ({backstop}); Kin MCP tools, Edit, and Write stay available"
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

        let hook = &parsed["hooks"]["PreToolUse"][0];
        assert_eq!(hook["matcher"], "Grep|Glob|Read");
        let script = profile
            .files
            .iter()
            .find(|f| f.relative_path == Path::new(CLAUDE_HOOK_SCRIPT))
            .expect("hook script present");
        assert!(script.executable);
        assert!(script.contents.contains("exit 2"));

        let args: Vec<String> = profile
            .extra_args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "--settings");
        assert!(args[1].ends_with(CLAUDE_SETTINGS_FILE));
    }

    #[test]
    fn claude_windows_arm_enforces_deny_rules_without_a_shell_hook() {
        let profile = ClaudeAdapter
            .semantic_only(Path::new("/tmp/profile"), true)
            .unwrap();
        assert_eq!(profile.tier, EnforcementTier::Enforced);
        assert!(profile
            .files
            .iter()
            .all(|f| f.relative_path != Path::new(CLAUDE_HOOK_SCRIPT)));
        let settings = profile
            .files
            .iter()
            .find(|f| f.relative_path == Path::new(CLAUDE_SETTINGS_FILE))
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&settings.contents).unwrap();
        assert!(parsed.get("hooks").is_none());
        assert!(profile.disclosure.contains("no hook backstop on Windows"));
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
