use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{KinError, Result};

/// High-level worldview preset for how Kin should treat non-code artifacts
/// and external tool execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorldPreset {
    /// Kin-first semantics, but keep compatibility projections for broad tools.
    Hybrid,
    /// Push non-code artifacts into Kin's world and avoid widening to file-first execution.
    Radical,
    /// Favor conventional workspace compatibility for existing codebases.
    Brownfield,
}

impl WorldPreset {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hybrid => "hybrid",
            Self::Radical => "radical",
            Self::Brownfield => "brownfield",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "hybrid" => Some(Self::Hybrid),
            "radical" => Some(Self::Radical),
            "brownfield" => Some(Self::Brownfield),
            _ => None,
        }
    }

    pub fn defaults(self) -> (NonCodeArtifactPolicy, ExternalToolExecutionPolicy) {
        match self {
            Self::Hybrid => (
                NonCodeArtifactPolicy::Semantic,
                ExternalToolExecutionPolicy::Workspace,
            ),
            Self::Radical => (
                NonCodeArtifactPolicy::Semantic,
                ExternalToolExecutionPolicy::Strict,
            ),
            Self::Brownfield => (
                NonCodeArtifactPolicy::Structured,
                ExternalToolExecutionPolicy::Workspace,
            ),
        }
    }
}

impl std::fmt::Display for WorldPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// How far Kin should pull non-code artifacts into its semantic model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonCodeArtifactPolicy {
    /// Prefer Kin-first artifact understanding where support exists.
    Semantic,
    /// Keep artifacts tracked and structured, but do not force a semantic worldview.
    Structured,
}

impl NonCodeArtifactPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Semantic => "semantic",
            Self::Structured => "structured",
        }
    }
}

impl std::fmt::Display for NonCodeArtifactPolicy {
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

/// Non-code artifact handling policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPolicyConfig {
    /// How strongly Kin should semanticize non-code artifacts.
    #[serde(default = "default_non_code_policy")]
    pub non_code: NonCodeArtifactPolicy,
}

impl Default for ArtifactPolicyConfig {
    fn default() -> Self {
        Self {
            non_code: default_non_code_policy(),
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

    /// Non-code artifact policy.
    #[serde(default)]
    pub artifacts: ArtifactPolicyConfig,

    /// External tool execution policy.
    #[serde(default)]
    pub execution: ExecutionPolicyConfig,
}

fn default_mode() -> String {
    "compat".to_string()
}

fn default_world_preset() -> WorldPreset {
    WorldPreset::Hybrid
}

fn default_non_code_policy() -> NonCodeArtifactPolicy {
    NonCodeArtifactPolicy::Semantic
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
            artifacts: ArtifactPolicyConfig::default(),
            execution: ExecutionPolicyConfig::default(),
        }
    }
}

impl KinConfig {
    /// Apply a worldview preset and synchronize the explicit policy knobs.
    pub fn apply_world_preset(&mut self, preset: WorldPreset) {
        let (non_code, external_tools) = preset.defaults();
        self.world.preset = preset;
        self.artifacts.non_code = non_code;
        self.execution.external_tools = external_tools;
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
        assert_eq!(parsed.world.preset, WorldPreset::Hybrid);
        assert_eq!(parsed.artifacts.non_code, NonCodeArtifactPolicy::Semantic);
        assert_eq!(
            parsed.execution.external_tools,
            ExternalToolExecutionPolicy::Workspace
        );
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let mut config = KinConfig::default();
        config.name = Some("test-repo".to_string());
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
        assert_eq!(config.world.preset, WorldPreset::Hybrid);
    }

    #[test]
    fn apply_world_preset_syncs_policy_knobs() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Brownfield);

        assert_eq!(config.world.preset, WorldPreset::Brownfield);
        assert_eq!(config.artifacts.non_code, NonCodeArtifactPolicy::Structured);
        assert_eq!(
            config.execution.external_tools,
            ExternalToolExecutionPolicy::Workspace
        );
    }
}
