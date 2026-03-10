use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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
                mcp_capable: false,
                mcp: None,
                wrapper_script: Some("kin-codex-wrapper".into()),
                env: HashMap::new(),
                cooperative: false,
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
    let guidance_path = layout.docs_dir().join(format!("{}-guide.md", kind.as_str()));
    std::fs::create_dir_all(layout.docs_dir())
        .map_err(|e| KinError::io(&layout.docs_dir(), e))?;
    let guidance = generate_guidance(kind);
    std::fs::write(&guidance_path, &guidance)
        .map_err(|e| KinError::io(&guidance_path, e))?;

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

    Ok(InstallResult {
        config_path,
        guidance_path,
        agents_md_path: if agents_md_created {
            Some(agents_md_path)
        } else {
            None
        },
        kind,
    })
}

/// Result of installing an assistant adapter.
#[derive(Debug)]
pub struct InstallResult {
    pub config_path: PathBuf,
    pub guidance_path: PathBuf,
    pub agents_md_path: Option<PathBuf>,
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
    let guidance_path = layout.docs_dir().join(format!("{}-guide.md", kind.as_str()));
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
        AssistantKind::ClaudeCode => format!(
            "# Kin + Claude Code\n\n\
             ## Setup\n\n\
             Claude Code connects to Kin via MCP (Model Context Protocol).\n\n\
             Add to your `.mcp.json`:\n\n\
             ```json\n\
             {{\n\
               \"mcpServers\": {{\n\
                 \"kin\": {{\n\
                   \"command\": \"kin\",\n\
                   \"args\": [\"mcp\"]\n\
                 }}\n\
               }}\n\
             }}\n\
             ```\n\n\
             ## Workflow\n\n\
             1. Kin provides semantic context packs instead of file dumps\n\
             2. Use `kin_context_pack` tool for precise, token-budgeted context\n\
             3. Use `kin_impact_analysis` before making changes\n\
             4. Use `kin_semantic_review` after making changes\n\
             5. Commit with `kin commit` for semantic history\n\n\
             ## Key Advantages\n\n\
             - Precise context under token budgets (no wasted tokens on irrelevant code)\n\
             - Semantic review shows entity-level impact, not line diffs\n\
             - Identity tracking survives renames and refactors\n"
        ),
        _ => format!(
            "# Kin + {name}\n\n\
             ## Setup\n\n\
             {setup}\n\n\
             ## Workflow\n\n\
             1. Use `kin context <entity>` for precise context\n\
             2. Use `kin review` for semantic impact analysis\n\
             3. Commit with `kin commit` for semantic history\n\n\
             ## Documentation\n\n\
             See AGENTS.md in the project root for the shared agent workflow guide.\n",
            name = kind,
            setup = if AssistantAdapterConfig::default_for(kind).mcp_capable {
                "This assistant supports MCP. Configure it to connect to `kin mcp`."
            } else {
                "This assistant does not support MCP directly. Use the CLI wrapper or direct CLI commands."
            }
        ),
    }
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
        assert_eq!(AssistantKind::from_str("claude"), Some(AssistantKind::ClaudeCode));
        assert_eq!(AssistantKind::from_str("gemini"), Some(AssistantKind::GeminiCli));
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
        assert!(!config.mcp_capable);
        assert!(!config.cooperative);
        assert!(config.wrapper_script.is_some());
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
        assert!(result.config_path.exists());
        assert!(result.guidance_path.exists());
        assert!(result.agents_md_path.is_some());

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
        assert!(report.checks.iter().any(|c| !c.passed && c.name == "Adapter config"));
    }

    #[test]
    fn doctor_reports_installed() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        install_adapter(&layout, AssistantKind::ClaudeCode).unwrap();

        let report = doctor(&layout, AssistantKind::ClaudeCode).unwrap();
        assert!(report.all_passed);
        let summary = report.summary();
        assert!(summary.contains("All checks passed"));
    }
}
