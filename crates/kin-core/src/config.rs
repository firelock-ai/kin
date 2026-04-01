// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{KinError, Result};

/// High-level worldview preset for how Kin should treat non-code artifacts
/// and external tool execution.
///
/// There is only one mode now — Native.  Legacy config values are accepted
/// by `from_str()` for backwards compatibility but always resolve to Native.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WorldPreset {
    /// Kin-native mode: graph is source of truth, files are projections.
    Native,
}

/// Custom deserialize: accept any legacy preset name and map to Native.
impl<'de> serde::Deserialize<'de> for WorldPreset {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // All values map to Native — there's only one mode now.
        match s.as_str() {
            "Native" | "native" | "compatibility" | "hybrid" | "brownfield" | "radical" => {
                Ok(Self::Native)
            }
            other => Err(serde::de::Error::custom(format!("unknown preset: {other}"))),
        }
    }
}

impl WorldPreset {
    pub fn as_str(&self) -> &'static str {
        "native"
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "native" | "compatibility" | "hybrid" | "brownfield" => Some(Self::Native),
            _ => None,
        }
    }

    pub fn defaults(self) -> ExternalToolExecutionPolicy {
        ExternalToolExecutionPolicy::Workspace
    }
}

impl std::fmt::Display for WorldPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// How Kin should handle broad external tools such as Docker Compose and Make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalToolExecutionPolicy {
    /// Widen broad tool execution to a full compatibility workspace when needed.
    Workspace,
    /// Do not auto-widen scoped execution for broad external tools.
    Strict,
}

impl ExternalToolExecutionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Strict => "strict",
        }
    }
}

impl std::fmt::Display for ExternalToolExecutionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// High-level world policy stored in repo config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldConfig {
    /// Named preset describing Kin's worldview for non-code artifacts.
    #[serde(default = "default_world_preset")]
    pub preset: WorldPreset,
}

impl Default for WorldConfig {
    fn default() -> Self {
        Self {
            preset: default_world_preset(),
        }
    }
}

/// Execution policy for external tools that expect a conventional workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicyConfig {
    /// How Kin should handle broad external tool execution.
    #[serde(default = "default_external_tool_policy")]
    pub external_tools: ExternalToolExecutionPolicy,
}

impl Default for ExecutionPolicyConfig {
    fn default() -> Self {
        Self {
            external_tools: default_external_tool_policy(),
        }
    }
}

/// Host kind for a Kin remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteHostKind {
    #[serde(rename = "github", alias = "git-hub")]
    GitHub,
    #[serde(rename = "gitlab", alias = "git-lab")]
    GitLab,
    #[serde(rename = "bitbucket", alias = "bit-bucket")]
    Bitbucket,
    #[serde(rename = "kinlab", alias = "kin-lab", alias = "kin-hub")]
    KinLab,
}

impl RemoteHostKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Bitbucket => "bitbucket",
            Self::KinLab => "kinlab",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "github" => Some(Self::GitHub),
            "gitlab" => Some(Self::GitLab),
            "bitbucket" => Some(Self::Bitbucket),
            "kinlab" => Some(Self::KinLab),
            _ => None,
        }
    }
}

impl std::fmt::Display for RemoteHostKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Transport kind for a Kin remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteTransportKind {
    GitExport,
    NativeKin,
}

impl RemoteTransportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitExport => "git-export",
            Self::NativeKin => "native-kin",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "git-export" => Some(Self::GitExport),
            "native-kin" => Some(Self::NativeKin),
            _ => None,
        }
    }
}

impl std::fmt::Display for RemoteTransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A configured Kin remote reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRefConfig {
    /// Remote name such as `origin`.
    pub name: String,
    /// Host type.
    pub host: RemoteHostKind,
    /// Transport type.
    pub transport: RemoteTransportKind,
    /// Optional remote URL or locator.
    #[serde(default)]
    pub url: Option<String>,
    /// Whether review state should publish with this remote.
    #[serde(default)]
    pub publish_review_state: bool,
    /// Whether proof state should publish with this remote.
    #[serde(default)]
    pub publish_proofs: bool,
}

/// Remote configuration stored in repo config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// Default remote name.
    #[serde(default)]
    pub default: Option<String>,
    /// Explicitly configured remotes.
    #[serde(default)]
    pub refs: Vec<RemoteRefConfig>,
}

/// Repo-local configuration stored in `.kin/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KinConfig {
    /// User-visible name for the repository.
    #[serde(default)]
    pub name: Option<String>,

    /// Default author for commits when not otherwise specified.
    #[serde(default)]
    pub default_author: Option<String>,

    /// Default branch name (created at init time).
    #[serde(default = "default_branch_name")]
    pub default_branch: String,

    /// Auto-index on file save (used by the daemon).
    #[serde(default = "default_true")]
    pub auto_index: bool,

    /// Token budget tiers for context pack builder.
    #[serde(default)]
    pub context: ContextConfig,

    /// Repository mode: "compat" (default) or "native".
    #[serde(default = "default_mode")]
    pub mode: String,

    /// High-level worldview preset for artifacts and execution.
    #[serde(default)]
    pub world: WorldConfig,

    /// External tool execution policy.
    #[serde(default)]
    pub execution: ExecutionPolicyConfig,

    /// Native and compatibility remote configuration.
    #[serde(default)]
    pub remote: RemoteConfig,
}

fn default_mode() -> String {
    "native".to_string()
}

fn default_world_preset() -> WorldPreset {
    WorldPreset::Native
}

fn default_external_tool_policy() -> ExternalToolExecutionPolicy {
    ExternalToolExecutionPolicy::Workspace
}

fn default_branch_name() -> String {
    "main".to_string()
}

fn default_true() -> bool {
    true
}

/// Context-pack builder configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConfig {
    /// Default token budget.
    #[serde(default = "default_token_budget")]
    pub default_budget: u32,
}

fn default_token_budget() -> u32 {
    8000
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            default_budget: default_token_budget(),
        }
    }
}

impl Default for KinConfig {
    fn default() -> Self {
        Self {
            name: None,
            default_author: None,
            default_branch: default_branch_name(),
            auto_index: true,
            context: ContextConfig::default(),
            mode: default_mode(),
            world: WorldConfig::default(),
            execution: ExecutionPolicyConfig::default(),
            remote: RemoteConfig::default(),
        }
    }
}

impl KinConfig {
    /// Apply a worldview preset and synchronize the explicit policy knobs.
    pub fn apply_world_preset(&mut self, preset: WorldPreset) {
        self.world.preset = preset;
        self.execution.external_tools = preset.defaults();
    }

    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| KinError::io(path, e))?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Load config or return defaults when the repo does not have a config yet.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default())
        }
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents).map_err(|e| KinError::io(path, e))?;
        Ok(())
    }

    /// Resolve a configured remote by explicit name or default remote.
    pub fn resolve_remote(&self, requested: Option<&str>) -> Option<&RemoteRefConfig> {
        let name = requested.or(self.remote.default.as_deref())?;
        self.remote.refs.iter().find(|remote| remote.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips() {
        let config = KinConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: KinConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.default_branch, "main");
        assert!(parsed.auto_index);
        assert_eq!(parsed.context.default_budget, 8000);
        assert_eq!(parsed.world.preset, WorldPreset::Native);
        assert_eq!(
            parsed.execution.external_tools,
            ExternalToolExecutionPolicy::Workspace
        );
        assert!(parsed.remote.refs.is_empty());
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let config = KinConfig {
            name: Some("test-repo".to_string()),
            ..KinConfig::default()
        };
        config.save(&path).unwrap();

        let loaded = KinConfig::load(&path).unwrap();
        assert_eq!(loaded.name, Some("test-repo".to_string()));
        assert_eq!(loaded.default_branch, "main");
    }

    #[test]
    fn partial_toml_uses_defaults() {
        let toml_str = r#"
name = "partial"
"#;
        let config: KinConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.name, Some("partial".to_string()));
        assert_eq!(config.default_branch, "main");
        assert!(config.auto_index);
        assert_eq!(config.world.preset, WorldPreset::Native);
        assert!(config.remote.refs.is_empty());
    }

    #[test]
    fn apply_world_preset_syncs_policy_knobs() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Native);

        assert_eq!(config.world.preset, WorldPreset::Native);
        assert_eq!(
            config.execution.external_tools,
            ExternalToolExecutionPolicy::Workspace
        );
    }

    #[test]
    fn remote_config_round_trips() {
        let mut config = KinConfig::default();
        config.remote.default = Some("origin".to_string());
        config.remote.refs.push(RemoteRefConfig {
            name: "origin".to_string(),
            host: RemoteHostKind::GitHub,
            transport: RemoteTransportKind::GitExport,
            url: Some("https://github.com/firelock-ai/kin.git".to_string()),
            publish_review_state: false,
            publish_proofs: false,
        });

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: KinConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.remote.default.as_deref(), Some("origin"));
        assert_eq!(parsed.remote.refs.len(), 1);
        assert_eq!(
            parsed.remote.refs[0].transport,
            RemoteTransportKind::GitExport
        );
    }

    #[test]
    fn remote_config_accepts_legacy_host_aliases() {
        let legacy = r#"
[remote]
default = "origin"

[[remote.refs]]
name = "origin"
host = "kin-hub"
transport = "native-kin"
"#;

        let parsed: KinConfig = toml::from_str(legacy).unwrap();
        assert_eq!(parsed.remote.refs.len(), 1);
        assert_eq!(parsed.remote.refs[0].host, RemoteHostKind::KinLab);
    }
}
