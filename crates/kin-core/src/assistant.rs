use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::assistant_sync::{sync_doc, ManagedDocConfig, ManagedDocTarget, RepoSummary};
use crate::error::{KinError, Result};
use crate::layout::KinLayout;

/// Known assistant types with their default configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssistantKind {
    ClaudeCode,
    Codex,
    GeminiCli,
    Cursor,
    Generic,
}

impl AssistantKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssistantKind::ClaudeCode => "claude-code",
            AssistantKind::Codex => "codex",
            AssistantKind::GeminiCli => "gemini-cli",
            AssistantKind::Cursor => "cursor",
            AssistantKind::Generic => "generic",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "claude-code" | "claude" => Some(Self::ClaudeCode),
            "codex" | "openai-codex" => Some(Self::Codex),
            "gemini-cli" | "gemini" => Some(Self::GeminiCli),
            "cursor" => Some(Self::Cursor),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }
}

impl std::fmt::Display for AssistantKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Configuration for an assistant adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantAdapterConfig {
    /// Which assistant this config targets.
    pub kind: AssistantKind,

    /// Display name for the assistant.
    pub display_name: String,

    /// Whether this assistant supports MCP natively.
    pub mcp_capable: bool,

    /// MCP connection config (if applicable).
    #[serde(default)]
    pub mcp: Option<McpConfig>,

    /// Wrapper script path (if MCP not supported natively).
    #[serde(default)]
    pub wrapper_script: Option<String>,

    /// Custom environment variables to set.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Whether the assistant supports cooperative intent registration.
    #[serde(default)]
    pub cooperative: bool,
}

/// MCP connection configuration for an assistant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Transport type: "stdio" or "socket".
    pub transport: String,

    /// Command to launch the MCP server (for stdio).
    #[serde(default)]
    pub command: Option<String>,

    /// Arguments for the command.
    #[serde(default)]
    pub args: Vec<String>,

    /// Socket path (for socket transport).
    #[serde(default)]
    pub socket_path: Option<String>,
}

impl AssistantAdapterConfig {
    /// Create a default config for a known assistant kind.
    pub fn default_for(kind: AssistantKind) -> Self {
        match kind {
            AssistantKind::ClaudeCode => Self {
                kind,
                display_name: "Claude Code".into(),
                mcp_capable: true,
                mcp: Some(McpConfig {
                    transport: "stdio".into(),
                    command: Some("kin".into()),
                    args: vec!["mcp".into()],
                    socket_path: None,
                }),
                wrapper_script: None,
                env: HashMap::new(),
                cooperative: true,
            },
            AssistantKind::Codex => Self {
                kind,
                display_name: "Codex".into(),
                mcp_capable: true,
                mcp: Some(McpConfig {
                    transport: "stdio".into(),
                    command: Some("kin".into()),
                    args: vec!["mcp".into()],
                    socket_path: None,
                }),
                wrapper_script: None,
                env: HashMap::new(),
                cooperative: true,
            },
            AssistantKind::GeminiCli => Self {
                kind,
                display_name: "Gemini CLI".into(),
                mcp_capable: true,
                mcp: Some(McpConfig {
                    transport: "stdio".into(),
                    command: Some("kin".into()),
                    args: vec!["mcp".into()],
                    socket_path: None,
                }),
                wrapper_script: None,
                env: HashMap::new(),
                cooperative: true,
            },
            AssistantKind::Cursor => Self {
                kind,
                display_name: "Cursor".into(),
                mcp_capable: true,
                mcp: Some(McpConfig {
                    transport: "stdio".into(),
                    command: Some("kin".into()),
                    args: vec!["mcp".into()],
                    socket_path: None,
                }),
                wrapper_script: None,
                env: HashMap::new(),
                cooperative: true,
            },
            AssistantKind::Generic => Self {
                kind,
                display_name: "Generic Assistant".into(),
                mcp_capable: false,
                mcp: None,
                wrapper_script: None,
                env: HashMap::new(),
                cooperative: false,
            },
        }
    }

    /// Load an adapter config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| KinError::io(path, e))?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save an adapter config to a TOML file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| KinError::io(parent, e))?;
        }
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents).map_err(|e| KinError::io(path, e))?;
        Ok(())
    }

    /// Config file path for this adapter within the .kin layout.
    pub fn config_path(layout: &KinLayout, kind: AssistantKind) -> PathBuf {
        layout
            .adapters_dir()
            .join(format!("{}.toml", kind.as_str()))
    }
}

/// Install an assistant adapter into a Kin repository.
///
/// Creates the adapter config file and generates guidance docs.
pub fn install_adapter(layout: &KinLayout, kind: AssistantKind) -> Result<InstallResult> {
    let config = AssistantAdapterConfig::default_for(kind);
    let config_path = AssistantAdapterConfig::config_path(layout, kind);

    // Create adapters directory
    std::fs::create_dir_all(layout.adapters_dir())
        .map_err(|e| KinError::io(&layout.adapters_dir(), e))?;

    // Save adapter config
    config.save(&config_path)?;

    // Generate guidance doc
    let guidance_path = layout
        .docs_dir()
        .join(format!("{}-guide.md", kind.as_str()));
    std::fs::create_dir_all(layout.docs_dir()).map_err(|e| KinError::io(&layout.docs_dir(), e))?;
    let guidance = generate_guidance(kind);
    std::fs::write(&guidance_path, &guidance).map_err(|e| KinError::io(&guidance_path, e))?;

    // Generate shared AGENTS.md if it doesn't exist
    let agents_md_path = layout.working_dir().join("AGENTS.md");
    let agents_md_created = if !agents_md_path.exists() {
        let agents_md = generate_agents_md();
        std::fs::write(&agents_md_path, &agents_md)
            .map_err(|e| KinError::io(&agents_md_path, e))?;
        true
    } else {
        false
    };

    let assistant_doc_path = ensure_assistant_target(layout, kind)?;

    Ok(InstallResult {
        config_path,
        guidance_path,
        agents_md_path: if agents_md_created {
            Some(agents_md_path)
        } else {
            None
        },
        assistant_doc_path,
        kind,
    })
}

/// Result of installing an assistant adapter.
#[derive(Debug)]
pub struct InstallResult {
    pub config_path: PathBuf,
    pub guidance_path: PathBuf,
    pub agents_md_path: Option<PathBuf>,
    pub assistant_doc_path: Option<PathBuf>,
    pub kind: AssistantKind,
}

/// List installed adapters in the repository.
pub fn list_adapters(layout: &KinLayout) -> Result<Vec<AssistantAdapterConfig>> {
    let dir = layout.adapters_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut configs = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| KinError::io(&dir, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| KinError::io(&dir, e))?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "toml") {
            match AssistantAdapterConfig::load(&path) {
                Ok(config) => configs.push(config),
                Err(e) => {
                    tracing::warn!("Failed to load adapter config {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(configs)
}

/// Run connectivity checks for an installed adapter.
pub fn doctor(layout: &KinLayout, kind: AssistantKind) -> Result<DoctorReport> {
    let config_path = AssistantAdapterConfig::config_path(layout, kind);
    let mut checks = Vec::new();

    // Check config file exists
    if config_path.exists() {
        checks.push(DoctorCheck {
            name: "Adapter config".into(),
            passed: true,
            detail: format!("Found at {}", config_path.display()),
        });
    } else {
        checks.push(DoctorCheck {
            name: "Adapter config".into(),
            passed: false,
            detail: format!("Missing: {}", config_path.display()),
        });
    }

    // Check guidance doc
    let guidance_path = layout
        .docs_dir()
        .join(format!("{}-guide.md", kind.as_str()));
    checks.push(DoctorCheck {
        name: "Guidance doc".into(),
        passed: guidance_path.exists(),
        detail: if guidance_path.exists() {
            format!("Found at {}", guidance_path.display())
        } else {
            "Missing; run `kin assistant install` to generate".into()
        },
    });

    // Check AGENTS.md
    let agents_path = layout.working_dir().join("AGENTS.md");
    checks.push(DoctorCheck {
        name: "AGENTS.md".into(),
        passed: agents_path.exists(),
        detail: if agents_path.exists() {
            "Found in project root".into()
        } else {
            "Missing; run `kin assistant install` to generate".into()
        },
    });

    if let Some(target_path) = assistant_target_path(kind) {
        let assistant_path = layout.working_dir().join(target_path);
        checks.push(DoctorCheck {
            name: target_path.into(),
            passed: assistant_path.exists(),
            detail: if assistant_path.exists() {
                format!("Found in project root ({})", assistant_path.display())
            } else {
                format!("Missing; run `kin assistant install {}` or `kin assistant sync`", kind)
            },
        });
    }

    // Check managed block in assistant-specific doc
    if let Some(target_path) = assistant_target_path(kind) {
        let assistant_path = layout.working_dir().join(target_path);
        if assistant_path.exists() {
            let content = std::fs::read_to_string(&assistant_path).unwrap_or_default();
            let has_managed = content.contains("<!-- kin:begin -->");
            checks.push(DoctorCheck {
                name: format!("{} managed block", target_path),
                passed: has_managed,
                detail: if has_managed {
                    "Kin managed block found".into()
                } else {
                    "No managed block; run `kin assistant sync` to generate".into()
                },
            });
        }
    }

    // Check MCP config (.mcp.json)
    let mcp_json_path = layout.working_dir().join(".mcp.json");
    if mcp_json_path.exists() {
        let mcp_content = std::fs::read_to_string(&mcp_json_path).unwrap_or_default();
        let has_kin = mcp_content.contains("\"kin\"");
        checks.push(DoctorCheck {
            name: "MCP config (.mcp.json)".into(),
            passed: has_kin,
            detail: if has_kin {
                "Found with kin entry".into()
            } else {
                "Found but missing kin server entry".into()
            },
        });
    } else {
        checks.push(DoctorCheck {
            name: "MCP config (.mcp.json)".into(),
            passed: false,
            detail: "Not found; create with `kin assistant snippets` or manually".into(),
        });
    }

    // Check sync config (.kin/assistant-sync.toml)
    let sync_path = layout.root().join("assistant-sync.toml");
    if sync_path.exists() {
        let sync_content = std::fs::read_to_string(&sync_path).unwrap_or_default();
        let target_name = assistant_target_path(kind).unwrap_or("AGENTS.md");
        let target_enabled = sync_content.contains(target_name);
        checks.push(DoctorCheck {
            name: "Sync config".into(),
            passed: target_enabled,
            detail: if target_enabled {
                format!("assistant-sync.toml has {} target", target_name)
            } else {
                format!(
                    "assistant-sync.toml missing {} target; run `kin assistant configure --enable {}`",
                    target_name, target_name
                )
            },
        });
    } else {
        checks.push(DoctorCheck {
            name: "Sync config".into(),
            passed: false,
            detail: "No assistant-sync.toml; run `kin assistant sync` to create".into(),
        });
    }

    // Check kin binary on PATH
    let kin_on_path = std::process::Command::new("kin")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    checks.push(DoctorCheck {
        name: "Kin binary on PATH".into(),
        passed: kin_on_path,
        detail: if kin_on_path {
            "kin command found on PATH".into()
        } else {
            "kin not found on PATH; MCP server requires kin to be available".into()
        },
    });

    // Check daemon connectivity (basic: check if .kin/ exists)
    checks.push(DoctorCheck {
        name: "Kin repository".into(),
        passed: layout.root().exists(),
        detail: if layout.root().exists() {
            format!("Found at {}", layout.root().display())
        } else {
            "Not a Kin repository".into()
        },
    });

    let all_passed = checks.iter().all(|c| c.passed);

    Ok(DoctorReport {
        kind,
        checks,
        all_passed,
    })
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Doctor report for an assistant.
#[derive(Debug)]
pub struct DoctorReport {
    pub kind: AssistantKind,
    pub checks: Vec<DoctorCheck>,
    pub all_passed: bool,
}

impl DoctorReport {
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        writeln!(out, "Doctor report for {}", self.kind).unwrap();
        for check in &self.checks {
            let icon = if check.passed { "OK" } else { "FAIL" };
            writeln!(out, "  [{}] {}: {}", icon, check.name, check.detail).unwrap();
        }
        if self.all_passed {
            writeln!(out, "\nAll checks passed.").unwrap();
        } else {
            writeln!(out, "\nSome checks failed.").unwrap();
        }
        out
    }
}

fn generate_guidance(kind: AssistantKind) -> String {
    match kind {
        AssistantKind::ClaudeCode => {
            "# Kin + Claude Code\n\n\
             ## Recommended Setup\n\n\
             - Native MCP: `claude mcp add kin -- kin mcp`\n\
             - Optional project-scoped MCP: keep a repo-local `.mcp.json` when you want portable setup.\n\
             - Repo instructions: keep `AGENTS.md` and `CLAUDE.md` enabled with `kin assistant sync`.\n\
             - Hooks: use Claude hooks for reminders like running `kin review` before mutation or `kin commit` after a validated change.\n\
             - Skills / plugins: optional accelerators, but Kin CLI + MCP should be the baseline.\n\n\
             ## Workflow\n\n\
             1. Read `AGENTS.md`, then `CLAUDE.md`.\n\
             2. Prefer `kin support`, `kin search`, `kin context`, and `kin review` before broad file scans.\n\
             3. Use MCP tools when connected; fall back to direct Kin CLI commands when needed.\n\
             4. Commit with `kin commit` for semantic history.\n"
                .to_string()
        }
        AssistantKind::Codex => {
            "# Kin + Codex\n\n\
             ## Recommended Setup\n\n\
             - Native MCP: `codex mcp add kin -- kin mcp`\n\
             - Repo instructions: keep `AGENTS.md` and `CODEX.md` enabled with `kin assistant sync`.\n\
             - Local config: Codex supports MCP and other overrides from `~/.codex/config.toml`.\n\
             - Keep direct Kin CLI instructions in guidance because Codex still benefits from explicit command-shaped prompts.\n\n\
             ## Workflow\n\n\
             1. Read `AGENTS.md`, then `CODEX.md`.\n\
             2. Prefer `kin support`, `kin search`, `kin context`, `kin review`, and `kin verify` before `rg` / `sed` loops.\n\
             3. Use MCP when available; direct Kin CLI remains a first-class path.\n\
             4. Commit with `kin commit` for semantic history.\n"
                .to_string()
        }
        AssistantKind::GeminiCli => {
            "# Kin + Gemini CLI\n\n\
             ## Recommended Setup\n\n\
             - Native MCP: `gemini mcp add kin -- kin mcp`\n\
             - Repo instructions: keep `AGENTS.md` and `GEMINI.md` enabled with `kin assistant sync`.\n\
             - Local settings: Gemini CLI reads persistent settings from `~/.gemini/settings.json`.\n\
             - Keep Kin CLI instructions explicit; Gemini benefits from narrow command-oriented context.\n\n\
             ## Workflow\n\n\
             1. Read `AGENTS.md`, then `GEMINI.md`.\n\
             2. Prefer `kin support`, `kin search`, `kin context`, `kin review`, and `kin verify` before broad repo scans.\n\
             3. Use MCP if configured; otherwise drive Kin directly from the CLI.\n\
             4. Commit with `kin commit` for semantic history.\n"
                .to_string()
        }
        _ => format!(
            "# Kin + {name}\n\n\
             ## Setup\n\n\
             {setup}\n\n\
             ## Workflow\n\n\
             1. Use `kin support` to understand repo coverage.\n\
             2. Use `kin context <entity>` for precise context.\n\
             3. Use `kin review` before merging.\n\
             4. Commit with `kin commit` for semantic history.\n\n\
             ## Documentation\n\n\
             See `AGENTS.md` in the project root for the shared workflow guide.\n",
            name = kind,
            setup = if AssistantAdapterConfig::default_for(kind).mcp_capable {
                "This assistant supports MCP. Configure it to connect to `kin mcp`."
            } else {
                "Use Kin CLI commands directly and keep repo-local guidance files current."
            }
        ),
    }
}

fn assistant_target_path(kind: AssistantKind) -> Option<&'static str> {
    match kind {
        AssistantKind::ClaudeCode => Some("CLAUDE.md"),
        AssistantKind::Codex => Some("CODEX.md"),
        AssistantKind::GeminiCli => Some("GEMINI.md"),
        _ => None,
    }
}

fn ensure_assistant_target(layout: &KinLayout, kind: AssistantKind) -> Result<Option<PathBuf>> {
    let Some(target_path) = assistant_target_path(kind) else {
        return Ok(None);
    };

    let mut config = ManagedDocConfig::load(layout)?;
    if let Some(existing) = config.targets.iter_mut().find(|t| t.path == target_path) {
        existing.enabled = true;
    } else {
        config.targets.push(ManagedDocTarget {
            path: target_path.into(),
            enabled: true,
            sections: vec!["summary".into(), "conventions".into(), "bootstrap".into()],
        });
    }

    let target = config
        .targets
        .iter()
        .find(|t| t.path == target_path)
        .expect("assistant target must exist")
        .clone();
    config.save(layout)?;

    let file_path = layout.working_dir().join(target_path);
    if !file_path.exists() {
        let content = crate::assistant_sync::generate_managed_content(&target, &RepoSummary::default());
        let _ = sync_doc(&file_path, &content)?;
    }

    Ok(Some(file_path))
}

fn generate_agents_md() -> String {
    "# Agent Workflow Guide\n\n\
     This repository uses Kin as its semantic version control system.\n\n\
     ## For AI Assistants\n\n\
     ### Getting Context\n\n\
     Use `kin context <entity_name>` to get a token-budgeted context pack.\n\
     This gives you precise, relevant code — not entire files.\n\n\
     ### Making Changes\n\n\
     1. Check impact before editing: `kin review`\n\
     2. Edit files normally\n\
     3. Kin tracks changes at the entity level (functions, classes, etc.)\n\n\
     ### Committing\n\n\
     Use `kin commit -m \"message\"` instead of `git commit`.\n\
     Kin commits are semantic — they track entity changes, not line diffs.\n\n\
     ### Reviewing\n\n\
     `kin review` shows:\n\
     - Changed entities (added, modified, removed)\n\
     - Downstream impact (callers, dependents, contracts, tests)\n\
     - Risk assessment (breaking changes, coverage gaps)\n\n\
     ## For Human Developers\n\n\
     - `kin status` — see working copy changes\n\
     - `kin review` — semantic review\n\
     - `kin bench` — performance and quality metrics\n\
     - `kin context <entity>` — get context for an entity\n"
        .to_string()
}

/// A ready-to-paste config snippet for assistant setup.
#[derive(Debug, Clone)]
pub struct ConfigSnippet {
    pub filename: String,
    pub description: String,
    pub content: String,
    pub target_path: String,
}

/// Generate ready-to-paste config snippets for assistant setup.
///
/// Each snippet is a self-contained configuration block that users can paste
/// into the appropriate file. All snippets emphasize that direct Kin CLI
/// commands (`kin search`, `kin context`, `kin review`, `kin commit`) are the
/// PRIMARY path; MCP is a convenience layer on top.
pub fn generate_config_snippets(kind: AssistantKind) -> Vec<ConfigSnippet> {
    match kind {
        AssistantKind::ClaudeCode => vec![
            ConfigSnippet {
                filename: ".mcp.json".into(),
                description: "Project-scoped MCP config for Claude Code. \
                    Place in your project root so Claude Code auto-discovers the Kin MCP server. \
                    Note: direct CLI commands (kin search, kin context, kin review, kin commit) \
                    are always available and are the primary workflow."
                    .into(),
                content: r#"{
  "mcpServers": {
    "kin": {
      "command": "kin",
      "args": ["mcp"],
      "description": "Kin semantic VCS — search entities, get context packs, review changes"
    }
  }
}"#
                .into(),
                target_path: ".mcp.json (project root)".into(),
            },
            ConfigSnippet {
                filename: "settings.json".into(),
                description: "Claude hooks snippet for .claude/settings.json. \
                    Hooks remind Claude to use Kin commands at key moments. \
                    Merge this into your existing settings.json if you have one."
                    .into(),
                content: r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hook": "echo 'Reminder: run `kin review` after edits to check semantic impact.'"
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hook": "echo 'Tip: use `kin search <name>` and `kin context <entity>` for precise lookups instead of grep/find.'"
      }
    ]
  }
}"#
                .into(),
                target_path: ".claude/settings.json".into(),
            },
        ],
        AssistantKind::Codex => vec![ConfigSnippet {
            filename: "config.toml".into(),
            description: "MCP config for Codex. Add this to your Codex config file. \
                Note: direct CLI commands (kin search, kin context, kin review, kin commit) \
                are always available and are the primary workflow."
                .into(),
            content: r#"[mcp_servers.kin]
command = "kin"
args = ["mcp"]"#
                .into(),
            target_path: "~/.codex/config.toml".into(),
        }],
        AssistantKind::GeminiCli => vec![ConfigSnippet {
            filename: "settings.json".into(),
            description: "MCP settings for Gemini CLI. Add this to your Gemini settings. \
                Note: direct CLI commands (kin search, kin context, kin review, kin commit) \
                are always available and are the primary workflow."
                .into(),
            content: r#"{
  "mcpServers": {
    "kin": {
      "command": "kin",
      "args": ["mcp"]
    }
  }
}"#
            .into(),
            target_path: "~/.gemini/settings.json".into(),
        }],
        _ => vec![],
    }
}

/// Write config snippets to `.kin/docs/assistant-config/<kind>/` and return
/// the paths of the written files.
pub fn write_config_snippets(layout: &KinLayout, kind: AssistantKind) -> Result<Vec<PathBuf>> {
    let snippets = generate_config_snippets(kind);
    if snippets.is_empty() {
        return Ok(vec![]);
    }

    let dir = layout
        .docs_dir()
        .join("assistant-config")
        .join(kind.as_str());
    std::fs::create_dir_all(&dir).map_err(|e| KinError::io(&dir, e))?;

    let mut paths = Vec::new();
    for snippet in &snippets {
        let path = dir.join(&snippet.filename);
        // Write a header comment followed by the snippet content
        let full_content = format!(
            "# {}\n# Target: {}\n#\n# Kin CLI-first: use `kin search`, `kin context`, `kin review`, `kin commit`\n# directly. MCP is a convenience layer.\n\n{}",
            snippet.description.lines().next().unwrap_or(""),
            snippet.target_path,
            snippet.content,
        );
        std::fs::write(&path, &full_content).map_err(|e| KinError::io(&path, e))?;
        paths.push(path);
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assistant_kind_roundtrip() {
        for kind in [
            AssistantKind::ClaudeCode,
            AssistantKind::Codex,
            AssistantKind::GeminiCli,
            AssistantKind::Cursor,
            AssistantKind::Generic,
        ] {
            let s = kind.as_str();
            let parsed = AssistantKind::from_str(s).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn assistant_kind_from_aliases() {
        assert_eq!(
            AssistantKind::from_str("claude"),
            Some(AssistantKind::ClaudeCode)
        );
        assert_eq!(
            AssistantKind::from_str("gemini"),
            Some(AssistantKind::GeminiCli)
        );
        assert_eq!(AssistantKind::from_str("unknown"), None);
    }

    #[test]
    fn default_config_claude_code() {
        let config = AssistantAdapterConfig::default_for(AssistantKind::ClaudeCode);
        assert!(config.mcp_capable);
        assert!(config.cooperative);
        assert!(config.mcp.is_some());
        assert_eq!(config.mcp.as_ref().unwrap().transport, "stdio");
    }

    #[test]
    fn default_config_codex() {
        let config = AssistantAdapterConfig::default_for(AssistantKind::Codex);
        assert!(config.mcp_capable);
        assert!(config.cooperative);
        assert!(config.mcp.is_some());
        assert!(config.wrapper_script.is_none());
    }

    #[test]
    fn config_toml_roundtrip() {
        let config = AssistantAdapterConfig::default_for(AssistantKind::ClaudeCode);
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AssistantAdapterConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.kind, AssistantKind::ClaudeCode);
        assert!(parsed.mcp_capable);
    }

    #[test]
    fn config_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude-code.toml");

        let config = AssistantAdapterConfig::default_for(AssistantKind::ClaudeCode);
        config.save(&path).unwrap();

        let loaded = AssistantAdapterConfig::load(&path).unwrap();
        assert_eq!(loaded.kind, AssistantKind::ClaudeCode);
        assert_eq!(loaded.display_name, "Claude Code");
    }

    #[test]
    fn install_adapter_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let result = install_adapter(&layout, AssistantKind::ClaudeCode).unwrap();
        let expected = dir.path().join("CLAUDE.md");
        assert!(result.config_path.exists());
        assert!(result.guidance_path.exists());
        assert!(result.agents_md_path.is_some());
        assert_eq!(result.assistant_doc_path.as_deref(), Some(expected.as_path()));
        assert!(expected.exists());

        // Verify config is loadable
        let config = AssistantAdapterConfig::load(&result.config_path).unwrap();
        assert_eq!(config.kind, AssistantKind::ClaudeCode);

        // Verify guidance content
        let guidance = std::fs::read_to_string(&result.guidance_path).unwrap();
        assert!(guidance.contains("Claude Code"));
        assert!(guidance.contains("MCP"));
    }

    #[test]
    fn install_adapter_does_not_overwrite_agents_md() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();

        // Pre-create AGENTS.md
        std::fs::write(dir.path().join("AGENTS.md"), "custom content").unwrap();

        let layout = KinLayout::new(kin_dir);
        let result = install_adapter(&layout, AssistantKind::Codex).unwrap();

        // Should not have created AGENTS.md (already exists)
        assert!(result.agents_md_path.is_none());
        assert!(result.assistant_doc_path.is_some());
        assert!(dir.path().join("CODEX.md").exists());

        // Existing content should be preserved
        let content = std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert_eq!(content, "custom content");
    }

    #[test]
    fn list_adapters_empty() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let adapters = list_adapters(&layout).unwrap();
        assert!(adapters.is_empty());
    }

    #[test]
    fn list_adapters_finds_installed() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        install_adapter(&layout, AssistantKind::ClaudeCode).unwrap();
        install_adapter(&layout, AssistantKind::Cursor).unwrap();

        let adapters = list_adapters(&layout).unwrap();
        assert_eq!(adapters.len(), 2);
    }

    #[test]
    fn doctor_reports_missing_config() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let report = doctor(&layout, AssistantKind::ClaudeCode).unwrap();
        assert!(!report.all_passed);
        assert!(report
            .checks
            .iter()
            .any(|c| !c.passed && c.name == "Adapter config"));
    }

    #[test]
    fn doctor_reports_installed() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        install_adapter(&layout, AssistantKind::ClaudeCode).unwrap();

        // Also create .mcp.json with kin entry so the MCP check passes
        std::fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers":{"kin":{"command":"kin","args":["mcp"]}}}"#,
        )
        .unwrap();

        let report = doctor(&layout, AssistantKind::ClaudeCode).unwrap();

        // Core file-based checks should pass
        let file_checks = ["Adapter config", "Guidance doc", "AGENTS.md", "CLAUDE.md",
                           "CLAUDE.md managed block", "MCP config (.mcp.json)", "Sync config", "Kin repository"];
        for name in &file_checks {
            let check = report.checks.iter().find(|c| c.name == *name);
            assert!(check.is_some(), "missing check: {}", name);
            assert!(check.unwrap().passed, "check failed: {}", name);
        }
    }

    #[test]
    fn config_snippets_claude_code() {
        let snippets = generate_config_snippets(AssistantKind::ClaudeCode);
        assert_eq!(snippets.len(), 2);

        // First snippet: .mcp.json
        let mcp_snippet = &snippets[0];
        assert_eq!(mcp_snippet.filename, ".mcp.json");
        assert!(mcp_snippet.content.contains("mcpServers"));
        assert!(mcp_snippet.content.contains("kin"));
        assert!(mcp_snippet.target_path.contains(".mcp.json"));

        // Second snippet: hooks
        let hooks_snippet = &snippets[1];
        assert_eq!(hooks_snippet.filename, "settings.json");
        assert!(hooks_snippet.content.contains("hooks"));
        assert!(hooks_snippet.content.contains("kin review"));
        assert!(hooks_snippet.target_path.contains(".claude/settings.json"));
    }

    #[test]
    fn config_snippets_codex() {
        let snippets = generate_config_snippets(AssistantKind::Codex);
        assert_eq!(snippets.len(), 1);

        let snippet = &snippets[0];
        assert_eq!(snippet.filename, "config.toml");
        assert!(snippet.content.contains("[mcp_servers.kin]"));
        assert!(snippet.content.contains("command = \"kin\""));
        assert!(snippet.target_path.contains("~/.codex/config.toml"));
    }

    #[test]
    fn write_config_snippets_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let paths = write_config_snippets(&layout, AssistantKind::ClaudeCode).unwrap();
        assert_eq!(paths.len(), 2);

        for path in &paths {
            assert!(path.exists(), "snippet file should exist: {}", path.display());
            let content = std::fs::read_to_string(path).unwrap();
            assert!(content.contains("Kin CLI-first"));
        }

        // Verify directory structure
        let config_dir = layout.docs_dir().join("assistant-config").join("claude-code");
        assert!(config_dir.exists());
        assert!(config_dir.join(".mcp.json").exists());
        assert!(config_dir.join("settings.json").exists());
    }

    #[test]
    fn doctor_checks_managed_block() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        install_adapter(&layout, AssistantKind::ClaudeCode).unwrap();

        // CLAUDE.md was created by install — it should have managed blocks
        let report = doctor(&layout, AssistantKind::ClaudeCode).unwrap();
        let managed_check = report.checks.iter().find(|c| c.name.contains("managed block"));
        assert!(managed_check.is_some());
        assert!(managed_check.unwrap().passed);
    }

    #[test]
    fn doctor_checks_mcp_config() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        // No .mcp.json yet
        let report = doctor(&layout, AssistantKind::ClaudeCode).unwrap();
        let mcp_check = report.checks.iter().find(|c| c.name.contains("MCP config"));
        assert!(mcp_check.is_some());
        assert!(!mcp_check.unwrap().passed);

        // Create .mcp.json with kin entry
        std::fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers":{"kin":{"command":"kin","args":["mcp"]}}}"#,
        )
        .unwrap();
        let report2 = doctor(&layout, AssistantKind::ClaudeCode).unwrap();
        let mcp_check2 = report2.checks.iter().find(|c| c.name.contains("MCP config"));
        assert!(mcp_check2.unwrap().passed);
    }
}
