// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use kin_model::ids::Hash256;
use kin_model::provenance::{Actor, ActorId, ActorKind};

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

    #[allow(clippy::should_implement_trait)]
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
                    args: vec!["mcp".into(), "start".into()],
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
                    args: vec!["mcp".into(), "start".into()],
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
                    args: vec!["mcp".into(), "start".into()],
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
                    args: vec!["mcp".into(), "start".into()],
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
        .map_err(|e| KinError::io(layout.adapters_dir(), e))?;

    // Save adapter config
    config.save(&config_path)?;

    // Generate guidance doc
    let guidance_path = layout
        .docs_dir()
        .join(format!("{}-guide.md", kind.as_str()));
    std::fs::create_dir_all(layout.docs_dir()).map_err(|e| KinError::io(layout.docs_dir(), e))?;
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
        if path.extension().is_some_and(|ext| ext == "toml") {
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
            verified: true,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Adapter config".into(),
            passed: false,
            detail: format!("Missing: {}", config_path.display()),
            verified: true,
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
        verified: true,
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
        verified: true,
    });

    if let Some(target_path) = assistant_target_path(kind) {
        let assistant_path = layout.working_dir().join(target_path);
        checks.push(DoctorCheck {
            name: target_path.into(),
            passed: assistant_path.exists(),
            detail: if assistant_path.exists() {
                format!("Found in project root ({})", assistant_path.display())
            } else {
                format!(
                    "Missing; run `kin assistant install {}` or `kin assistant sync`",
                    kind
                )
            },
            verified: true,
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
                verified: true,
            });
        }
    }

    // Check MCP config — assistant-specific paths
    match kind {
        AssistantKind::ClaudeCode => {
            // Claude uses repo-local .mcp.json for project-scoped MCP
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
                    verified: true,
                });
            } else {
                checks.push(DoctorCheck {
                    name: "MCP config (.mcp.json)".into(),
                    passed: false,
                    detail: "Not found; create with `kin assistant snippets claude-code` or `claude mcp add kin -- kin mcp start`".into(),
                    verified: true,
                });
            }
        }
        AssistantKind::Codex => {
            // Codex uses ~/.codex/config.toml — repo-local .mcp.json is not its
            // path, so this row is guidance and nothing here read a file. The
            // global registration IS checked further down; this row must not be
            // counted as a second, passing check of the same thing.
            checks.push(DoctorCheck::unverified(
                "MCP config (codex)",
                "not checked here — repo-local `.mcp.json` is not Codex's path. Run `codex mcp \
                 add kin -- kin mcp start` to register MCP globally; or see `kin assistant \
                 snippets codex`",
            ));
        }
        AssistantKind::GeminiCli => {
            // Gemini uses ~/.gemini/settings.json — same reasoning as Codex above.
            checks.push(DoctorCheck::unverified(
                "MCP config (gemini)",
                "not checked here — repo-local `.mcp.json` is not Gemini's path. Run `gemini mcp \
                 add kin -- kin mcp start` to register MCP globally; or see `kin assistant \
                 snippets gemini-cli`",
            ));
        }
        _ => {
            // Generic/Cursor — check .mcp.json as best-effort
            let mcp_json_path = layout.working_dir().join(".mcp.json");
            let exists = mcp_json_path.exists();
            checks.push(DoctorCheck {
                name: "MCP config".into(),
                passed: exists,
                detail: if exists {
                    "Found .mcp.json in project root".into()
                } else {
                    "No .mcp.json; configure MCP manually for your assistant".into()
                },
                verified: true,
            });
        }
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
            verified: true,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Sync config".into(),
            passed: false,
            detail: "No assistant-sync.toml; run `kin assistant sync` to create".into(),
            verified: true,
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
        verified: true,
    });

    // Check global MCP registration for Claude Code
    if kind == AssistantKind::ClaudeCode {
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() {
            let settings_path = std::path::PathBuf::from(&home)
                .join(".claude")
                .join("settings.json");
            let alt_path = std::path::PathBuf::from(&home).join(".claude.json");

            let (found, detail) = if settings_path.exists() {
                let content = std::fs::read_to_string(&settings_path).unwrap_or_default();
                if content.contains("\"kin\"") {
                    (
                        true,
                        format!("MCP 'kin' found in {}", settings_path.display()),
                    )
                } else {
                    (
                        false,
                        format!(
                            "MCP 'kin' not found in {}; run `claude mcp add kin -- kin mcp start`",
                            settings_path.display()
                        ),
                    )
                }
            } else if alt_path.exists() {
                let content = std::fs::read_to_string(&alt_path).unwrap_or_default();
                if content.contains("\"kin\"") {
                    (true, format!("MCP 'kin' found in {}", alt_path.display()))
                } else {
                    (
                        false,
                        format!(
                            "MCP 'kin' not found in {}; run `claude mcp add kin -- kin mcp start`",
                            alt_path.display()
                        ),
                    )
                }
            } else {
                (
                    false,
                    "No Claude settings found; run `claude mcp add kin -- kin mcp start`".into(),
                )
            };

            checks.push(DoctorCheck {
                name: "Global MCP registration".into(),
                passed: found,
                detail,
                verified: true,
            });
        }
    }

    // Check global MCP registration for Codex
    if kind == AssistantKind::Codex {
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() {
            let config_path = std::path::PathBuf::from(&home)
                .join(".codex")
                .join("config.toml");
            let (found, detail) = if config_path.exists() {
                let content = std::fs::read_to_string(&config_path).unwrap_or_default();
                if content.contains("[mcp_servers") && content.contains("kin") {
                    (
                        true,
                        format!("MCP 'kin' found in {}", config_path.display()),
                    )
                } else {
                    (
                        false,
                        format!(
                            "MCP 'kin' not found in {}; run `codex mcp add kin -- kin mcp start`",
                            config_path.display()
                        ),
                    )
                }
            } else {
                (
                    false,
                    "No Codex config found; run `codex mcp add kin -- kin mcp start`".into(),
                )
            };

            checks.push(DoctorCheck {
                name: "Global MCP registration".into(),
                passed: found,
                detail,
                verified: true,
            });
        }
    }

    // Check global MCP registration for Gemini CLI
    if kind == AssistantKind::GeminiCli {
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() {
            let settings_path = std::path::PathBuf::from(&home)
                .join(".gemini")
                .join("settings.json");
            let (found, detail) = if settings_path.exists() {
                let content = std::fs::read_to_string(&settings_path).unwrap_or_default();
                if content.contains("\"kin\"") {
                    (
                        true,
                        format!("MCP 'kin' found in {}", settings_path.display()),
                    )
                } else {
                    (
                        false,
                        format!(
                            "MCP 'kin' not found in {}; run `gemini mcp add kin -- kin mcp start`",
                            settings_path.display()
                        ),
                    )
                }
            } else {
                (
                    false,
                    "No Gemini settings found; run `gemini mcp add kin -- kin mcp start`".into(),
                )
            };

            checks.push(DoctorCheck {
                name: "Global MCP registration".into(),
                passed: found,
                detail,
                verified: true,
            });
        }
    }

    // Check daemon connectivity (basic: check if .kin/ exists)
    checks.push(DoctorCheck {
        name: "Kin repository".into(),
        passed: layout.root().exists(),
        detail: if layout.root().exists() {
            format!("Found at {}", layout.root().display())
        } else {
            "Not a Kin repository".into()
        },
        verified: true,
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
    /// Whether this row was actually checked.
    ///
    /// Two rows cannot be: an assistant whose MCP registration lives in a global
    /// config this process has no reliable path to reports `passed` because
    /// nothing contradicted it, not because anything was read. A summary that
    /// folds those into "All checks passed" claims a completeness it never
    /// established, which is the same defect `graph validate` carried when it
    /// reported a clean bill on a graph missing every cross-file edge.
    ///
    /// Defaulted true so a serialized report written before this field existed
    /// reads as fully checked rather than as wholly unverified.
    #[serde(default = "check_is_verified_by_default")]
    pub verified: bool,
}

fn check_is_verified_by_default() -> bool {
    true
}

impl DoctorCheck {
    /// A row this process actually established.
    pub fn checked(name: impl Into<String>, passed: bool, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed,
            detail: detail.into(),
            verified: true,
        }
    }

    /// A row nothing could establish, carried so the reader sees the gap rather
    /// than an absence they cannot distinguish from a pass.
    pub fn unverified(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: true,
            detail: detail.into(),
            verified: false,
        }
    }
}

/// Doctor report for an assistant.
#[derive(Debug)]
pub struct DoctorReport {
    pub kind: AssistantKind,
    pub checks: Vec<DoctorCheck>,
    pub all_passed: bool,
}

impl DoctorReport {
    /// Names of the rows nothing established, in report order.
    pub fn unverified_checks(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|check| !check.verified)
            .map(|check| check.name.as_str())
            .collect()
    }

    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        writeln!(out, "Doctor report for {}", self.kind).unwrap();
        for check in &self.checks {
            let icon = if !check.verified {
                "SKIP"
            } else if check.passed {
                "OK"
            } else {
                "FAIL"
            };
            writeln!(out, "  [{}] {}: {}", icon, check.name, check.detail).unwrap();
        }
        // A verdict states which question it answered. A row nothing could read
        // is not a row that passed, and folding it into "All checks passed" is
        // the same unqualified completeness claim `graph validate` used to make
        // about a graph whose integrity was all it had checked.
        let unverified = self.unverified_checks();
        if !self.all_passed {
            writeln!(out, "\nSome checks failed.").unwrap();
        } else if unverified.is_empty() {
            writeln!(out, "\nAll checks passed.").unwrap();
        } else {
            writeln!(
                out,
                "\nEvery check that could run passed. Not covered by that: {}. A [SKIP] row was \
                 not read here, so this report does not say whether it is configured.",
                unverified.join(", ")
            )
            .unwrap();
        }
        out
    }
}

fn generate_guidance(kind: AssistantKind) -> String {
    match kind {
        AssistantKind::ClaudeCode => {
            "# Kin + Claude Code\n\n\
             ## Recommended Setup\n\n\
             - Native MCP: `claude mcp add kin -- kin mcp start`\n\
             - Quick MCP-only try: `claude mcp add kin -- npx -y kin-mcp`\n\
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
             - Native MCP: `codex mcp add kin -- kin mcp start`\n\
             - Quick MCP-only try: `codex mcp add kin -- npx -y kin-mcp`\n\
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
             - Native MCP: `gemini mcp add kin -- kin mcp start`\n\
             - Quick MCP-only try: `gemini mcp add kin -- npx -y kin-mcp`\n\
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
                "This assistant supports MCP. Configure it to connect to `kin mcp start`."
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
        let content =
            crate::assistant_sync::generate_managed_content(&target, &RepoSummary::default());
        let _ = sync_doc(&file_path, &content)?;
    }

    Ok(Some(file_path))
}

// ---------------------------------------------------------------------------
// Prompt generation engine
// ---------------------------------------------------------------------------

/// Mode for prompt generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptMode {
    /// Full guidance for production use
    Normal,
    /// Compact guidance (~200 tokens) for benchmark runs
    Benchmark,
}

/// Generate injectable prompt guidance for an assistant.
///
/// Returns a compact text block designed to be prepended to assistant prompts.
/// Content adapts based on assistant kind and mode.
pub fn generate_assistant_prompt(
    kind: AssistantKind,
    mode: PromptMode,
    _layout: &KinLayout,
    summary: Option<&RepoSummary>,
) -> String {
    let mut out = String::new();

    // Compact benchmark content (shared by both modes)
    out.push_str("# Kin - Native Semantic Repository\n\n");
    out.push_str("This repository uses Kin as the semantic system of record. ");
    out.push_str("The graph is authority; files are the projection and execution surface. ");
    out.push_str("Use Kin tools instead of grep/find/cat for code discovery.\n\n");
    out.push_str("## Quick Start\n");
    out.push_str("1. MCP: `semantic_locate` to find the right entity or file by meaning\n");
    out.push_str("2. MCP: `get_context_pack` to load the focused neighborhood\n");
    out.push_str(
        "3. MCP: `trace_data_flow` when lineage or cross-file dependency direction matters\n",
    );
    out.push_str("4. CLI: `kin overview --compact` to get codebase orientation\n");
    out.push_str("5. CLI: `kin trace <ExactName> --compact` to resolve one entity and print the focused neighborhood\n");
    out.push_str(
        "6. CLI: `kin search <name> --show-body --limit 5` for exact-name lookup with inline body\n",
    );
    out.push_str("7. CLI: `kin context <entity>` to get the full token-budgeted context pack\n\n");
    out.push_str("## Key Principle\n");
    out.push_str(
        "Ask the graph first, read projected files second, and use raw filesystem reads last.\n",
    );

    // Append summary stats if available
    if let Some(s) = summary {
        out.push('\n');
        let mut langs: Vec<_> = s.language_breakdown.iter().collect();
        langs.sort_by(|a, b| b.1.cmp(a.1));
        let lang_str: Vec<String> = langs.iter().map(|(k, _)| k.to_string()).collect();
        let lang_display = if lang_str.is_empty() {
            "unknown".to_string()
        } else {
            lang_str.join(", ")
        };
        out.push_str(&format!(
            "Repository: {} entities, {}\n",
            s.entity_count, lang_display
        ));
    }

    if mode == PromptMode::Benchmark {
        return out;
    }

    // Normal mode: add extended guidance
    out.push('\n');
    out.push_str(&crate::assistant_sync::render_comparison_tables());
    out.push_str(&crate::assistant_sync::render_quick_reference());

    // MCP tool mapping for MCP-capable assistants
    let adapter = AssistantAdapterConfig::default_for(kind);
    if adapter.mcp_capable {
        out.push_str(&crate::assistant_sync::render_mcp_tool_mapping());
    }

    // Assistant-specific tips
    match kind {
        AssistantKind::ClaudeCode => {
            out.push_str("## Claude Code Tips\n\n");
            out.push_str(
                "- CLAUDE.md is managed by Kin — keep your notes outside the managed block.\n",
            );
            out.push_str("- Configure MCP: `claude mcp add kin -- kin mcp start`\n");
            out.push_str("- Quick MCP-only try: `claude mcp add kin -- npx -y kin-mcp`\n");
            out.push_str("- Use hooks for reminders: `kin review` before mutation, `kin commit` after changes.\n");
            out.push('\n');
        }
        AssistantKind::Codex => {
            out.push_str("## Codex Tips\n\n");
            out.push_str("- AGENTS.md contains Kin guidance — read it first.\n");
            out.push_str("- Configure MCP: `codex mcp add kin -- kin mcp start`\n");
            out.push_str("- Quick MCP-only try: `codex mcp add kin -- npx -y kin-mcp`\n");
            out.push_str("- Prefer `kin search` and `kin context` over `rg` / `sed` loops.\n");
            out.push('\n');
        }
        AssistantKind::GeminiCli => {
            out.push_str("## Gemini CLI Tips\n\n");
            out.push_str("- GEMINI.md contains Kin guidance — read it first.\n");
            out.push_str("- Configure MCP: `gemini mcp add kin -- kin mcp start`\n");
            out.push_str("- Quick MCP-only try: `gemini mcp add kin -- npx -y kin-mcp`\n");
            out.push_str("- Use narrow `kin context` packs instead of broad file reads.\n");
            out.push('\n');
        }
        _ => {}
    }

    out
}

/// Import top-level assistant doc files into `.kin/docs/imported/`.
/// Copies AGENTS.md, CLAUDE.md, CODEX.md, GEMINI.md (if they exist) to
/// `.kin/docs/imported/{name}.original.md`.
/// Returns paths of successfully imported files.
pub fn import_legacy_docs(layout: &KinLayout) -> Result<Vec<PathBuf>> {
    let legacy_names = ["AGENTS.md", "CLAUDE.md", "CODEX.md", "GEMINI.md"];
    let import_dir = layout.docs_dir().join("imported");
    std::fs::create_dir_all(&import_dir).map_err(|e| KinError::io(&import_dir, e))?;

    let mut imported = Vec::new();
    let working_dir = layout.working_dir();

    for name in &legacy_names {
        let src = working_dir.join(name);
        if src.exists() {
            let stem = Path::new(name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(name);
            let dest = import_dir.join(format!("{}.original.md", stem));
            let content = std::fs::read_to_string(&src).map_err(|e| KinError::io(&src, e))?;
            std::fs::write(&dest, &content).map_err(|e| KinError::io(&dest, e))?;
            imported.push(dest);
        }
    }

    Ok(imported)
}

/// Generate a compact bootstrap doc for the control root.
/// This replaces top-level AGENTS.md/CLAUDE.md etc in Kin-native mode.
pub fn generate_bootstrap_docs(_layout: &KinLayout, kind: AssistantKind) -> String {
    let adapter = AssistantAdapterConfig::default_for(kind);
    let assistant_name = &adapter.display_name;

    let mut out = String::new();
    out.push_str("# Kin-Native Repository\n\n");
    out.push_str("This repo uses Kin as the semantic system of record. Start with Kin graph tools, not broad filesystem discovery.\n\n");
    out.push_str("## Workflow\n");
    out.push_str("1. If MCP is connected, start with `semantic_locate` to find the right entity or file by meaning\n");
    out.push_str(
        "2. Use `get_context_pack` to load the focused neighborhood before reading broad files\n",
    );
    out.push_str(
        "3. Use `trace_data_flow` when lineage or cross-file dependency direction matters\n",
    );
    out.push_str(
        "4. Use `kin overview --compact` only for broad architecture/orientation questions\n",
    );
    out.push_str(
        "5. If MCP is unavailable, use `kin trace <ExactName> --compact` for exact named symbols\n",
    );
    out.push_str("6. `kin search <ExactName> --kind function --show-body --limit 5` only if trace is too coarse\n");
    out.push_str("7. `kin context <entity>` for the full pack\n\n");
    out.push_str("## Rules\n");
    out.push_str("- Prefer exact names like `parseStrict`, `parse`, or `$MyType`\n");
    out.push_str("- Avoid broad shotgun searches\n");
    out.push_str("- Native sessions shim normal file reads/searches to the managed source view when needed\n");
    out.push_str("- Legacy docs live under `.kin/docs/imported/`\n\n");

    out.push_str(&format!("## For {}\n", assistant_name));
    match kind {
        AssistantKind::ClaudeCode => {
            out.push_str("- Configure MCP: `claude mcp add kin -- kin mcp start`\n");
            out.push_str("- Quick MCP-only try: `claude mcp add kin -- npx -y kin-mcp`\n");
            out.push_str(
                "- CLAUDE.md is managed by Kin. Add custom notes outside the managed block.\n",
            );
            out.push_str("- Use Claude hooks for `kin review` before mutation and `kin commit` after changes.\n");
        }
        AssistantKind::Codex => {
            out.push_str("- Configure MCP: `codex mcp add kin -- kin mcp start`\n");
            out.push_str("- Quick MCP-only try: `codex mcp add kin -- npx -y kin-mcp`\n");
            out.push_str("- Prefer `kin search` and `kin context` over `rg` / `sed` loops.\n");
            out.push_str("- CODEX.md contains Kin-specific guidance.\n");
        }
        AssistantKind::GeminiCli => {
            out.push_str("- Configure MCP: `gemini mcp add kin -- kin mcp start`\n");
            out.push_str("- Quick MCP-only try: `gemini mcp add kin -- npx -y kin-mcp`\n");
            out.push_str("- Use narrow `kin context` packs for focused context.\n");
            out.push_str("- GEMINI.md contains Kin-specific guidance.\n");
        }
        AssistantKind::Cursor => {
            out.push_str("- Configure MCP via `.mcp.json` in the project root.\n");
            out.push_str("- Prefer `kin search` and `kin context` for code discovery.\n");
        }
        AssistantKind::Generic => {
            out.push_str(
                "- Use `kin search`, `kin context`, and `kin review` directly from CLI.\n",
            );
            out.push_str(
                "- No MCP configuration needed — CLI commands are the primary interface.\n",
            );
        }
    }
    out.push('\n');

    out
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
      "args": ["mcp", "start"],
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
                content: crate::hooks::render_hooks_json(&crate::hooks::generate_claude_hooks()),
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
args = ["mcp", "start"]
env = { KIN_MCP_TOOL_PROFILE = "agent-default" }"#
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
      "args": ["mcp", "start"]
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
        // JSON doesn't support comments — write raw. TOML/other get `#` headers.
        let is_json = snippet.filename.ends_with(".json");
        let full_content = if is_json {
            snippet.content.clone()
        } else {
            format!(
                "# {}\n# Target: {}\n#\n# Kin CLI-first: use `kin search`, `kin context`, `kin review`, `kin commit`\n# directly. MCP is a convenience layer.\n\n{}",
                snippet.description.lines().next().unwrap_or(""),
                snippet.target_path,
                snippet.content,
            )
        };
        std::fs::write(&path, &full_content).map_err(|e| KinError::io(&path, e))?;
        paths.push(path);
    }

    Ok(paths)
}

// ---------------------------------------------------------------------------
// Actor resolution from session context
// ---------------------------------------------------------------------------

/// Resolve an Actor from an agent session's assistant kind.
///
/// Maps `AssistantKind` to `ActorKind::Assistant`, creating a deterministic
/// `ActorId` from the `vendor` + `client_name` combination via SHA-256 hash.
pub fn resolve_actor_from_session(vendor: &str, client_name: &str, _kind: &AssistantKind) -> Actor {
    let key = format!("{}/{}", vendor, client_name);
    let hash = Sha256::digest(key.as_bytes());
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&hash);
    Actor {
        actor_id: ActorId::from_hash(Hash256::from_bytes(buf)),
        kind: ActorKind::Assistant,
        display_name: key,
        external_refs: Vec::new(),
    }
}

/// Resolve a human actor with a given name.
///
/// Creates a deterministic `ActorId` by hashing the name string.
pub fn resolve_human_actor(name: &str) -> Actor {
    let hash = Sha256::digest(name.as_bytes());
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&hash);
    Actor {
        actor_id: ActorId::from_hash(Hash256::from_bytes(buf)),
        kind: ActorKind::Human,
        display_name: name.to_string(),
        external_refs: Vec::new(),
    }
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
        assert_eq!(
            result.assistant_doc_path.as_deref(),
            Some(expected.as_path())
        );
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
            r#"{"mcpServers":{"kin":{"command":"kin","args":["mcp","start"]}}}"#,
        )
        .unwrap();

        let report = doctor(&layout, AssistantKind::ClaudeCode).unwrap();

        // Core file-based checks should pass
        let file_checks = [
            "Adapter config",
            "Guidance doc",
            "AGENTS.md",
            "CLAUDE.md",
            "CLAUDE.md managed block",
            "MCP config (.mcp.json)",
            "Sync config",
            "Kin repository",
        ];
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
            assert!(
                path.exists(),
                "snippet file should exist: {}",
                path.display()
            );
            let content = std::fs::read_to_string(path).unwrap();
            // JSON files are written raw (no comments); TOML gets # headers
            if path.extension().is_some_and(|e| e == "json") {
                // Must be valid JSON
                assert!(
                    serde_json::from_str::<serde_json::Value>(&content).is_ok(),
                    "JSON snippet must be valid JSON: {}",
                    path.display()
                );
            } else {
                assert!(content.contains("Kin CLI-first"));
            }
        }

        // Verify directory structure
        let config_dir = layout
            .docs_dir()
            .join("assistant-config")
            .join("claude-code");
        assert!(config_dir.exists());
        assert!(config_dir.join(".mcp.json").exists());
        assert!(config_dir.join("settings.json").exists());
    }

    /// FIR-2384. `graph validate` used to report "All checks passed" on a graph
    /// missing every cross-file edge; the CLI now narrows that to "All INTEGRITY
    /// checks passed" and prints what it did not check beside it. This surface
    /// made the same unqualified claim for a different reason: two of its rows
    /// report `passed` because nothing contradicted them, not because anything
    /// was read, and the summary folded them in.
    #[test]
    fn a_summary_does_not_call_an_unread_row_a_passed_check() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let report = doctor(&layout, AssistantKind::Codex).unwrap();
        let unread = report
            .checks
            .iter()
            .find(|check| check.name == "MCP config (codex)")
            .expect("the row is still reported, so the gap is visible");

        assert!(
            !unread.verified,
            "repo-local .mcp.json is not Codex's path, so nothing here read one"
        );
        assert!(
            unread.detail.contains("not checked here"),
            "the row says so in its own words: {}",
            unread.detail
        );
        assert_eq!(
            report.unverified_checks(),
            vec!["MCP config (codex)"],
            "and it is the only such row"
        );

        let summary = report.summary();
        assert!(
            summary.contains("[SKIP] MCP config (codex)"),
            "an unread row does not render as OK: {summary}"
        );
        assert!(
            !summary.contains("All checks passed."),
            "the unqualified claim is what FIR-2358 objected to: {summary}"
        );
    }

    /// The counterpart, so the qualification above cannot be unconditional: an
    /// assistant whose every row this process really can read still gets the
    /// plain sentence.
    #[test]
    fn an_assistant_whose_every_row_was_read_still_reports_all_checks_passed() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let report = doctor(&layout, AssistantKind::ClaudeCode).unwrap();
        assert!(
            report.unverified_checks().is_empty(),
            "every Claude Code row reads a path this process holds: {:?}",
            report.unverified_checks()
        );
        assert!(!report.summary().contains("[SKIP]"), "{}", report.summary());

        // A bare `.kin` directory fails the config rows, so the fixture above
        // reaches "Some checks failed." and cannot exercise the plain verdict
        // at all. Build the all-read, all-passed report directly, or the
        // sentence this test is named for goes unasserted while the test
        // passes.
        let clean = DoctorReport {
            kind: AssistantKind::ClaudeCode,
            checks: vec![DoctorCheck::checked("MCP config", true, "configured")],
            all_passed: true,
        };
        assert!(
            clean.summary().contains("All checks passed."),
            "nothing was skipped, so the verdict carries no qualification: {}",
            clean.summary()
        );
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
        let managed_check = report
            .checks
            .iter()
            .find(|c| c.name.contains("managed block"));
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
            r#"{"mcpServers":{"kin":{"command":"kin","args":["mcp","start"]}}}"#,
        )
        .unwrap();
        let report2 = doctor(&layout, AssistantKind::ClaudeCode).unwrap();
        let mcp_check2 = report2
            .checks
            .iter()
            .find(|c| c.name.contains("MCP config"));
        assert!(mcp_check2.unwrap().passed);
    }

    #[test]
    fn doctor_external_mcp_check_runs_claude() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);
        // Just verify it runs without panic — actual MCP may or may not exist
        let report = doctor(&layout, AssistantKind::ClaudeCode).unwrap();
        // Should have a "Global MCP registration" check (if HOME is set)
        if std::env::var("HOME").is_ok() {
            assert!(report
                .checks
                .iter()
                .any(|c| c.name == "Global MCP registration"));
        }
    }

    #[test]
    fn doctor_external_mcp_check_runs_codex() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);
        let report = doctor(&layout, AssistantKind::Codex).unwrap();
        if std::env::var("HOME").is_ok() {
            assert!(report
                .checks
                .iter()
                .any(|c| c.name == "Global MCP registration"));
        }
    }

    #[test]
    fn doctor_external_mcp_check_runs_gemini() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);
        let report = doctor(&layout, AssistantKind::GeminiCli).unwrap();
        if std::env::var("HOME").is_ok() {
            assert!(report
                .checks
                .iter()
                .any(|c| c.name == "Global MCP registration"));
        }
    }

    // -- Prompt generation tests --

    #[test]
    fn prompt_benchmark_mode_is_compact() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let prompt = generate_assistant_prompt(
            AssistantKind::ClaudeCode,
            PromptMode::Benchmark,
            &layout,
            None,
        );

        assert!(prompt.contains("# Kin - Native Semantic Repository"));
        assert!(prompt.contains("semantic_locate"));
        assert!(prompt.contains("get_context_pack"));
        assert!(prompt.contains("trace_data_flow"));
        assert!(prompt.contains("kin overview --compact"));
        assert!(prompt.contains("kin trace <ExactName>"));
        assert!(prompt.contains("kin search <name> --show-body --limit 5"));
        assert!(prompt.contains("kin context <entity>"));
        assert!(prompt.contains("Key Principle"));
        // Should NOT contain normal-mode content
        assert!(!prompt.contains("## Claude Code Tips"));
        assert!(!prompt.contains("MCP Tools"));
        assert!(!prompt.contains("Finding Code (use Kin instead"));
    }

    #[test]
    fn prompt_benchmark_mode_with_summary() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let mut langs = HashMap::new();
        langs.insert("Rust".into(), 200);
        langs.insert("TypeScript".into(), 100);
        let summary = RepoSummary {
            entity_count: 500,
            language_breakdown: langs,
            ..Default::default()
        };

        let prompt = generate_assistant_prompt(
            AssistantKind::Codex,
            PromptMode::Benchmark,
            &layout,
            Some(&summary),
        );

        assert!(prompt.contains("Repository: 500 entities"));
        assert!(prompt.contains("Rust"));
        assert!(prompt.contains("TypeScript"));
    }

    #[test]
    fn prompt_normal_mode_includes_tables_and_tips() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let prompt =
            generate_assistant_prompt(AssistantKind::ClaudeCode, PromptMode::Normal, &layout, None);

        // Should contain benchmark content
        assert!(prompt.contains("# Kin - Native Semantic Repository"));
        // Should contain comparison tables
        assert!(prompt.contains("Finding Code (use Kin instead"));
        assert!(prompt.contains("Reading Code (use Kin instead"));
        // Should contain MCP mapping (Claude is MCP-capable)
        assert!(prompt.contains("MCP Tools"));
        assert!(prompt.contains("semantic_locate"));
        assert!(prompt.contains("get_context_pack"));
        // Should contain Claude-specific tips
        assert!(prompt.contains("## Claude Code Tips"));
        assert!(prompt.contains("CLAUDE.md is managed by Kin"));
    }

    #[test]
    fn prompt_normal_mode_codex() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let prompt =
            generate_assistant_prompt(AssistantKind::Codex, PromptMode::Normal, &layout, None);

        assert!(prompt.contains("## Codex Tips"));
        assert!(prompt.contains("AGENTS.md contains Kin guidance"));
        assert!(prompt.contains("codex mcp add kin"));
        assert!(prompt.contains("MCP Tools"));
    }

    #[test]
    fn prompt_normal_mode_generic_no_mcp() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let prompt =
            generate_assistant_prompt(AssistantKind::Generic, PromptMode::Normal, &layout, None);

        // Generic is not MCP-capable
        assert!(!prompt.contains("MCP Tools"));
        // Should still have comparison tables
        assert!(prompt.contains("Finding Code (use Kin instead"));
    }

    #[test]
    fn prompt_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let p1 = generate_assistant_prompt(
            AssistantKind::ClaudeCode,
            PromptMode::Benchmark,
            &layout,
            None,
        );
        let p2 = generate_assistant_prompt(
            AssistantKind::ClaudeCode,
            PromptMode::Benchmark,
            &layout,
            None,
        );
        assert_eq!(p1, p2);
    }

    // -- import_legacy_docs tests --

    #[test]
    fn import_legacy_docs_copies_existing() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        // Create some legacy docs
        std::fs::write(dir.path().join("AGENTS.md"), "# My Agents").unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), "# Claude stuff").unwrap();

        let imported = import_legacy_docs(&layout).unwrap();
        assert_eq!(imported.len(), 2);

        let import_dir = layout.docs_dir().join("imported");
        let agents_orig = import_dir.join("AGENTS.original.md");
        let claude_orig = import_dir.join("CLAUDE.original.md");
        assert!(agents_orig.exists());
        assert!(claude_orig.exists());

        let content = std::fs::read_to_string(&agents_orig).unwrap();
        assert_eq!(content, "# My Agents");
    }

    #[test]
    fn import_legacy_docs_skips_missing() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        // No legacy docs exist
        let imported = import_legacy_docs(&layout).unwrap();
        assert!(imported.is_empty());
    }

    // -- generate_bootstrap_docs tests --

    #[test]
    fn bootstrap_docs_claude() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let doc = generate_bootstrap_docs(&layout, AssistantKind::ClaudeCode);
        assert!(doc.contains("Kin-Native Repository"));
        assert!(doc.contains("semantic_locate"));
        assert!(doc.contains("get_context_pack"));
        assert!(doc.contains("trace_data_flow"));
        assert!(doc.contains("kin overview --compact"));
        assert!(doc.contains("kin trace <ExactName>"));
        assert!(doc.contains("kin context <entity>"));
        assert!(doc.contains("## For Claude Code"));
        assert!(doc.contains("claude mcp add kin"));
        assert!(doc.contains("semantic system of record"));
        assert!(doc.contains(".kin/docs/imported/"));
    }

    #[test]
    fn bootstrap_docs_generic() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let doc = generate_bootstrap_docs(&layout, AssistantKind::Generic);
        assert!(doc.contains("## For Generic Assistant"));
        assert!(doc.contains("No MCP configuration needed"));
    }

    // -- Actor resolution tests --

    #[test]
    fn resolve_actor_from_session_deterministic() {
        let a1 = resolve_actor_from_session("anthropic", "claude-code", &AssistantKind::ClaudeCode);
        let a2 = resolve_actor_from_session("anthropic", "claude-code", &AssistantKind::ClaudeCode);
        assert_eq!(a1.actor_id.0, a2.actor_id.0);
        assert_eq!(a1.display_name, "anthropic/claude-code");
        assert!(matches!(a1.kind, ActorKind::Assistant));
    }

    #[test]
    fn resolve_actor_from_session_different_vendors() {
        let a1 = resolve_actor_from_session("anthropic", "claude-code", &AssistantKind::ClaudeCode);
        let a2 = resolve_actor_from_session("openai", "codex", &AssistantKind::Codex);
        assert_ne!(a1.actor_id.0, a2.actor_id.0);
    }

    #[test]
    fn resolve_human_actor_deterministic() {
        let a1 = resolve_human_actor("alice");
        let a2 = resolve_human_actor("alice");
        assert_eq!(a1.actor_id.0, a2.actor_id.0);
        assert_eq!(a1.display_name, "alice");
        assert!(matches!(a1.kind, ActorKind::Human));
    }

    #[test]
    fn resolve_human_actor_different_names() {
        let a1 = resolve_human_actor("alice");
        let a2 = resolve_human_actor("bob");
        assert_ne!(a1.actor_id.0, a2.actor_id.0);
    }
}
