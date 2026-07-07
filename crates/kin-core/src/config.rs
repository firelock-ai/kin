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

/// Proof posture for LSP enrichment. Mirrors `kin_lsp::ProofMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LspProofMode {
    /// Best-effort enrichment; gaps are recorded but not fatal.
    #[default]
    Advisory,
    /// Citable / proof run; required-language gaps and silent failures are fatal.
    Citable,
}

impl LspProofMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Citable => "citable",
        }
    }
}

impl std::fmt::Display for LspProofMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A per-language LSP provider override. Selects a specific language server for
/// a language and optionally overrides the binaries searched / launch args.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LspProviderOverride {
    /// Language slug, e.g. `python`, `rust`, `go`.
    pub language: String,
    /// Provider id to prefer, e.g. `pylsp`, `rust-analyzer`, `gopls`.
    pub provider: String,
    /// Extra binary-name candidates, tried before the provider's defaults.
    #[serde(default)]
    pub binaries: Vec<String>,
    /// Launch-arg override; when set, replaces the provider's default args.
    #[serde(default)]
    pub args: Option<Vec<String>>,
}

/// Repo-local LSP enrichment configuration, stored under `[lsp]` in
/// `.kin/config.toml`.
///
/// LSP is default-on enrichment layered over Kin's own parsers and linkers.
/// This section replaces environment sprawl (e.g. `KIN_DAEMON_DISABLE_LSP`) with
/// an explicit, versioned config surface. Provider selection here maps directly
/// into the `kin_lsp` provider registry (`RegistryConfig`): `providers` become
/// registry overrides, `required` / `disabled` become the registry's
/// required / disabled language policy, and `proof_mode` selects the enrichment
/// proof posture.
///
/// Field order matters for TOML serialization: the scalar and string-array keys
/// come first and `providers` (a TOML array-of-tables) is last, so a config with
/// provider overrides serializes without moving a key past the `[[lsp.providers]]`
/// section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspConfig {
    /// Whether LSP enrichment runs at all. Absent config means enabled with
    /// auto-detection of installed servers.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Proof posture for enrichment runs.
    #[serde(default)]
    pub proof_mode: LspProofMode,
    /// Languages whose enrichment is REQUIRED. A gap for a required language is
    /// fail-loud in a citable proof run.
    #[serde(default)]
    pub required: Vec<String>,
    /// Languages whose enrichment is disabled entirely.
    #[serde(default)]
    pub disabled: Vec<String>,
    /// Per-language provider overrides.
    #[serde(default)]
    pub providers: Vec<LspProviderOverride>,
}

impl Default for LspConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proof_mode: LspProofMode::Advisory,
            required: Vec::new(),
            disabled: Vec::new(),
            providers: Vec::new(),
        }
    }
}

impl LspConfig {
    /// Validate the section for internal consistency, independent of which
    /// servers are installed. Fail-loud: a language cannot be both required and
    /// disabled. Provider-id and language-slug validation against the live
    /// registry happens when this section is mapped into
    /// `kin_lsp::RegistryConfig`.
    pub fn validate(&self) -> Result<()> {
        for language in &self.required {
            if self
                .disabled
                .iter()
                .any(|disabled| disabled.eq_ignore_ascii_case(language))
            {
                return Err(KinError::Config(format!(
                    "language '{language}' is both required and disabled in [lsp] config"
                )));
            }
        }
        Ok(())
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

    /// External tool execution policy.
    #[serde(default)]
    pub execution: ExecutionPolicyConfig,

    /// Native and compatibility remote configuration.
    #[serde(default)]
    pub remote: RemoteConfig,

    /// LSP enrichment configuration: provider selection, required/disabled
    /// languages, and proof posture.
    #[serde(default)]
    pub lsp: LspConfig,
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
            lsp: LspConfig::default(),
        }
    }
}

impl KinConfig {
    /// Apply a worldview preset and synchronize the explicit policy knobs.
    pub fn apply_world_preset(&mut self, preset: WorldPreset) {
        self.world.preset = preset;
        self.execution.external_tools = preset.defaults();
    }

    /// Validate cross-field invariants that serde cannot express on its own.
    /// Fail-loud: a config that contradicts a substrate contract must not load
    /// silently and degrade behavior at runtime.
    pub fn validate(&self) -> Result<()> {
        self.lsp.validate()?;
        Ok(())
    }

    /// Load config from a TOML file. The parsed config is validated before it is
    /// returned, so a contradictory config fails loud at load rather than
    /// silently degrading enrichment later.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| KinError::io(path, e))?;
        let config: Self = toml::from_str(&contents)?;
        config.validate()?;
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

    #[test]
    fn lsp_config_defaults_to_enabled_advisory() {
        let config = KinConfig::default();
        assert!(config.lsp.enabled);
        assert_eq!(config.lsp.proof_mode, LspProofMode::Advisory);
        assert!(config.lsp.providers.is_empty());
        assert!(config.lsp.required.is_empty());
        assert!(config.lsp.disabled.is_empty());
    }

    #[test]
    fn lsp_config_absent_section_uses_defaults() {
        let config: KinConfig = toml::from_str("name = \"no-lsp-section\"").unwrap();
        assert!(config.lsp.enabled);
        assert_eq!(config.lsp.proof_mode, LspProofMode::Advisory);
    }

    #[test]
    fn lsp_section_parses_typed_fields() {
        let toml_str = r#"
[lsp]
enabled = true
proof_mode = "citable"
required = ["rust", "python"]
disabled = ["go"]

[[lsp.providers]]
language = "python"
provider = "pylsp"
binaries = ["/opt/py/pylsp"]
args = ["--verbose"]
"#;
        let config: KinConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.lsp.proof_mode, LspProofMode::Citable);
        assert_eq!(config.lsp.required, vec!["rust", "python"]);
        assert_eq!(config.lsp.disabled, vec!["go"]);
        assert_eq!(config.lsp.providers.len(), 1);
        let over = &config.lsp.providers[0];
        assert_eq!(over.language, "python");
        assert_eq!(over.provider, "pylsp");
        assert_eq!(over.binaries, vec!["/opt/py/pylsp"]);
        assert_eq!(over.args.as_deref(), Some(&["--verbose".to_string()][..]));
    }

    #[test]
    fn lsp_proof_mode_display_round_trips() {
        assert_eq!(LspProofMode::Advisory.as_str(), "advisory");
        assert_eq!(LspProofMode::Citable.to_string(), "citable");
    }

    #[test]
    fn lsp_required_and_disabled_conflict_is_rejected() {
        let config = LspConfig {
            required: vec!["rust".to_string()],
            disabled: vec!["Rust".to_string()],
            ..LspConfig::default()
        };
        // Case-insensitive, fail-loud.
        assert!(config.validate().is_err());
    }

    #[test]
    fn load_rejects_contradictory_lsp_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[lsp]\nrequired = [\"rust\"]\ndisabled = [\"rust\"]\n",
        )
        .unwrap();
        // A contradictory config must fail at load, not silently degrade later.
        assert!(KinConfig::load(&path).is_err());
    }

    #[test]
    fn lsp_provider_override_round_trips_through_save() {
        // With a non-empty `providers` array-of-tables, `save()` only produces
        // valid TOML if `providers` is the last field of the section — this
        // exercises that ordering end to end.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = KinConfig::default();
        config.lsp.proof_mode = LspProofMode::Citable;
        config.lsp.required = vec!["rust".to_string()];
        config.lsp.providers = vec![LspProviderOverride {
            language: "rust".to_string(),
            provider: "rust-analyzer".to_string(),
            binaries: vec![],
            args: None,
        }];
        config.save(&path).unwrap();

        let loaded = KinConfig::load(&path).unwrap();
        assert_eq!(loaded.lsp.proof_mode, LspProofMode::Citable);
        assert_eq!(loaded.lsp.required, vec!["rust"]);
        assert_eq!(loaded.lsp.providers.len(), 1);
        assert_eq!(loaded.lsp.providers[0].provider, "rust-analyzer");
    }
}
