use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{KinError, Result};

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
}

fn default_mode() -> String {
    "compat".to_string()
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
        }
    }
}

impl KinConfig {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| KinError::io(path, e))?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
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
    }
}
