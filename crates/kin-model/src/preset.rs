// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The three operational presets that control reconcile engine behavior.
///
/// Each preset maps to a concrete `ReconcilePolicy` via `to_policy()`.
/// Users pick a preset in their workspace config; individual policy fields
/// can be overridden on top.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldPreset {
    /// Strict mode for greenfield Kin-native projects and CI.
    /// Rejects broken ASTs, treats files as ephemeral graph views.
    KinNative,
    /// Forgiving mode for migrating existing repos.
    /// Falls back to LKG on broken ASTs, preserves formatting, maintains Git shadow.
    #[default]
    Brownfield,
    /// Fast mode optimized for AI agent token budgets.
    /// Strips non-essential formatting, strict semantic validation.
    AgentExecution,
}

/// What to do when the AST parse is broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokenAstBehavior {
    /// Reject the file outright; no fallback.
    Reject,
    /// Fall back to the Last Known Good snapshot.
    FallbackToLkg,
}

/// How to handle human-readable formatting during projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormattingPolicy {
    /// Preserve original formatting, comments, and whitespace.
    Preserve,
    /// Strip comments, collapse whitespace, drop non-essential formatting.
    Strip,
    /// Minimal: keep only enough formatting for valid syntax.
    Minimal,
}

/// How much content to emit during projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionMode {
    /// Full projection with all formatting and comments.
    Full,
    /// Compact projection optimized for agent token budgets.
    Compact,
}

/// How strict semantic validation should be during reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    /// All semantic constraints enforced; broken structure rejected.
    Strict,
    /// Best-effort validation; warnings instead of errors where possible.
    Lenient,
}

/// Concrete policy that the reconcile engine consumes.
///
/// Built from a `WorldPreset` via `to_policy()`, then optionally patched
/// with per-field overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcilePolicy {
    pub broken_ast_behavior: BrokenAstBehavior,
    pub formatting_policy: FormattingPolicy,
    pub git_shadow: bool,
    pub projection_mode: ProjectionMode,
    pub validation_strictness: ValidationLevel,
}

impl Default for ReconcilePolicy {
    fn default() -> Self {
        WorldPreset::default().to_policy()
    }
}

impl WorldPreset {
    /// Map this preset to its concrete reconcile policy.
    pub fn to_policy(self) -> ReconcilePolicy {
        match self {
            WorldPreset::KinNative => ReconcilePolicy {
                broken_ast_behavior: BrokenAstBehavior::Reject,
                formatting_policy: FormattingPolicy::Minimal,
                git_shadow: false,
                projection_mode: ProjectionMode::Full,
                validation_strictness: ValidationLevel::Strict,
            },
            WorldPreset::Brownfield => ReconcilePolicy {
                broken_ast_behavior: BrokenAstBehavior::FallbackToLkg,
                formatting_policy: FormattingPolicy::Preserve,
                git_shadow: true,
                projection_mode: ProjectionMode::Full,
                validation_strictness: ValidationLevel::Lenient,
            },
            WorldPreset::AgentExecution => ReconcilePolicy {
                broken_ast_behavior: BrokenAstBehavior::Reject,
                formatting_policy: FormattingPolicy::Strip,
                git_shadow: false,
                projection_mode: ProjectionMode::Compact,
                validation_strictness: ValidationLevel::Strict,
            },
        }
    }
}

/// Trait that the reconcile engine uses to query policy decisions.
pub trait ReconcilePolicyProvider {
    fn broken_ast_behavior(&self) -> BrokenAstBehavior;
    fn formatting_policy(&self) -> FormattingPolicy;
    fn should_maintain_git_shadow(&self) -> bool;
    fn projection_mode(&self) -> ProjectionMode;
    fn validation_strictness(&self) -> ValidationLevel;
}

impl ReconcilePolicyProvider for ReconcilePolicy {
    fn broken_ast_behavior(&self) -> BrokenAstBehavior {
        self.broken_ast_behavior
    }

    fn formatting_policy(&self) -> FormattingPolicy {
        self.formatting_policy
    }

    fn should_maintain_git_shadow(&self) -> bool {
        self.git_shadow
    }

    fn projection_mode(&self) -> ProjectionMode {
        self.projection_mode
    }

    fn validation_strictness(&self) -> ValidationLevel {
        self.validation_strictness
    }
}

/// Optional per-field overrides applied on top of a preset.
///
/// Each `None` field means "use the preset default".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_ast_behavior: Option<BrokenAstBehavior>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatting_policy: Option<FormattingPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_shadow: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection_mode: Option<ProjectionMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_strictness: Option<ValidationLevel>,
}

impl PolicyOverrides {
    /// Apply overrides on top of a base policy, returning the merged result.
    pub fn apply_to(&self, base: &ReconcilePolicy) -> ReconcilePolicy {
        ReconcilePolicy {
            broken_ast_behavior: self.broken_ast_behavior.unwrap_or(base.broken_ast_behavior),
            formatting_policy: self.formatting_policy.unwrap_or(base.formatting_policy),
            git_shadow: self.git_shadow.unwrap_or(base.git_shadow),
            projection_mode: self.projection_mode.unwrap_or(base.projection_mode),
            validation_strictness: self
                .validation_strictness
                .unwrap_or(base.validation_strictness),
        }
    }
}

/// Workspace-level preset configuration, serializable to TOML/JSON.
///
/// Supports a top-level preset with optional overrides, plus per-directory
/// preset overrides for sub-modules that need different behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetConfig {
    /// The base preset for the workspace.
    #[serde(default)]
    pub preset: WorldPreset,
    /// Per-field overrides applied on top of the preset.
    #[serde(default)]
    pub overrides: PolicyOverrides,
    /// Per-directory preset overrides. Key is a relative directory path.
    /// Each entry can specify a different preset and/or overrides.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub directory_presets: HashMap<String, DirectoryPreset>,
}

impl PresetConfig {
    /// Resolve the effective policy for the workspace root.
    pub fn resolve_root_policy(&self) -> ReconcilePolicy {
        let base = self.preset.to_policy();
        self.overrides.apply_to(&base)
    }

    /// Resolve the effective policy for a given directory path.
    ///
    /// Walks from the most specific directory override to the root,
    /// applying the first matching directory preset on top of the root policy.
    pub fn resolve_policy_for(&self, dir_path: &str) -> ReconcilePolicy {
        // Find the most specific (longest) matching directory prefix.
        let mut best_match: Option<&DirectoryPreset> = None;
        let mut best_len = 0;

        for (prefix, dir_preset) in &self.directory_presets {
            let normalized = prefix.trim_end_matches('/');
            if (dir_path == normalized || dir_path.starts_with(&format!("{normalized}/")))
                && normalized.len() > best_len
            {
                best_match = Some(dir_preset);
                best_len = normalized.len();
            }
        }

        match best_match {
            Some(dir_preset) => {
                // Start from the directory's preset (or fall back to root preset).
                let base_preset = dir_preset.preset.unwrap_or(self.preset);
                let base = base_preset.to_policy();
                // Apply root overrides first, then directory overrides.
                let with_root = self.overrides.apply_to(&base);
                dir_preset.overrides.apply_to(&with_root)
            }
            None => self.resolve_root_policy(),
        }
    }
}

/// Per-directory preset override.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryPreset {
    /// Override the preset for this directory. None = inherit from parent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<WorldPreset>,
    /// Per-field overrides for this directory.
    #[serde(default)]
    pub overrides: PolicyOverrides,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preset_is_brownfield() {
        assert_eq!(WorldPreset::default(), WorldPreset::Brownfield);
    }

    #[test]
    fn default_policy_is_brownfield() {
        let policy = ReconcilePolicy::default();
        let brownfield = WorldPreset::Brownfield.to_policy();
        assert_eq!(policy, brownfield);
    }

    #[test]
    fn kin_native_policy() {
        let policy = WorldPreset::KinNative.to_policy();
        assert_eq!(policy.broken_ast_behavior, BrokenAstBehavior::Reject);
        assert_eq!(policy.formatting_policy, FormattingPolicy::Minimal);
        assert!(!policy.git_shadow);
        assert_eq!(policy.projection_mode, ProjectionMode::Full);
        assert_eq!(policy.validation_strictness, ValidationLevel::Strict);
    }

    #[test]
    fn brownfield_policy() {
        let policy = WorldPreset::Brownfield.to_policy();
        assert_eq!(policy.broken_ast_behavior, BrokenAstBehavior::FallbackToLkg);
        assert_eq!(policy.formatting_policy, FormattingPolicy::Preserve);
        assert!(policy.git_shadow);
        assert_eq!(policy.projection_mode, ProjectionMode::Full);
        assert_eq!(policy.validation_strictness, ValidationLevel::Lenient);
    }

    #[test]
    fn agent_execution_policy() {
        let policy = WorldPreset::AgentExecution.to_policy();
        assert_eq!(policy.broken_ast_behavior, BrokenAstBehavior::Reject);
        assert_eq!(policy.formatting_policy, FormattingPolicy::Strip);
        assert!(!policy.git_shadow);
        assert_eq!(policy.projection_mode, ProjectionMode::Compact);
        assert_eq!(policy.validation_strictness, ValidationLevel::Strict);
    }

    #[test]
    fn policy_override_on_preset() {
        let base = WorldPreset::Brownfield.to_policy();
        let overrides = PolicyOverrides {
            git_shadow: Some(false),
            validation_strictness: Some(ValidationLevel::Strict),
            ..Default::default()
        };
        let merged = overrides.apply_to(&base);

        // Overridden fields
        assert!(!merged.git_shadow);
        assert_eq!(merged.validation_strictness, ValidationLevel::Strict);

        // Non-overridden fields remain from Brownfield
        assert_eq!(merged.broken_ast_behavior, BrokenAstBehavior::FallbackToLkg);
        assert_eq!(merged.formatting_policy, FormattingPolicy::Preserve);
        assert_eq!(merged.projection_mode, ProjectionMode::Full);
    }

    #[test]
    fn empty_overrides_are_identity() {
        let base = WorldPreset::KinNative.to_policy();
        let overrides = PolicyOverrides::default();
        let merged = overrides.apply_to(&base);
        assert_eq!(merged, base);
    }

    #[test]
    fn preset_serialization_roundtrip() {
        for preset in [
            WorldPreset::KinNative,
            WorldPreset::Brownfield,
            WorldPreset::AgentExecution,
        ] {
            let json = serde_json::to_string(&preset).unwrap();
            let parsed: WorldPreset = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, preset);
        }
    }

    #[test]
    fn policy_serialization_roundtrip() {
        for preset in [
            WorldPreset::KinNative,
            WorldPreset::Brownfield,
            WorldPreset::AgentExecution,
        ] {
            let policy = preset.to_policy();
            let json = serde_json::to_string(&policy).unwrap();
            let parsed: ReconcilePolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
    }

    #[test]
    fn preset_config_serialization_roundtrip() {
        let config = PresetConfig {
            preset: WorldPreset::Brownfield,
            overrides: PolicyOverrides {
                git_shadow: Some(false),
                ..Default::default()
            },
            directory_presets: {
                let mut map = HashMap::new();
                map.insert(
                    "agents/".to_string(),
                    DirectoryPreset {
                        preset: Some(WorldPreset::AgentExecution),
                        overrides: PolicyOverrides::default(),
                    },
                );
                map
            },
        };
        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: PresetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn directory_preset_overrides_compose() {
        let config = PresetConfig {
            preset: WorldPreset::Brownfield,
            overrides: PolicyOverrides::default(),
            directory_presets: {
                let mut map = HashMap::new();
                map.insert(
                    "agents".to_string(),
                    DirectoryPreset {
                        preset: Some(WorldPreset::AgentExecution),
                        overrides: PolicyOverrides {
                            git_shadow: Some(true), // override: keep git shadow even for agents
                            ..Default::default()
                        },
                    },
                );
                map
            },
        };

        // Root resolves to Brownfield
        let root_policy = config.resolve_root_policy();
        assert_eq!(root_policy, WorldPreset::Brownfield.to_policy());

        // agents/ resolves to AgentExecution base + git_shadow override
        let agent_policy = config.resolve_policy_for("agents/worker");
        assert_eq!(agent_policy.broken_ast_behavior, BrokenAstBehavior::Reject);
        assert_eq!(agent_policy.formatting_policy, FormattingPolicy::Strip);
        assert!(agent_policy.git_shadow); // overridden to true
        assert_eq!(agent_policy.projection_mode, ProjectionMode::Compact);
        assert_eq!(agent_policy.validation_strictness, ValidationLevel::Strict);

        // Unmatched directory falls back to root
        let other_policy = config.resolve_policy_for("lib/utils");
        assert_eq!(other_policy, root_policy);
    }

    #[test]
    fn directory_preset_most_specific_wins() {
        let config = PresetConfig {
            preset: WorldPreset::Brownfield,
            overrides: PolicyOverrides::default(),
            directory_presets: {
                let mut map = HashMap::new();
                map.insert(
                    "src".to_string(),
                    DirectoryPreset {
                        preset: Some(WorldPreset::KinNative),
                        overrides: PolicyOverrides::default(),
                    },
                );
                map.insert(
                    "src/legacy".to_string(),
                    DirectoryPreset {
                        preset: Some(WorldPreset::Brownfield),
                        overrides: PolicyOverrides::default(),
                    },
                );
                map
            },
        };

        // src/app resolves to KinNative
        let src_policy = config.resolve_policy_for("src/app");
        assert_eq!(src_policy, WorldPreset::KinNative.to_policy());

        // src/legacy/old resolves to Brownfield (more specific match)
        let legacy_policy = config.resolve_policy_for("src/legacy/old");
        assert_eq!(legacy_policy, WorldPreset::Brownfield.to_policy());
    }

    #[test]
    fn reconcile_policy_provider_trait() {
        let policy = WorldPreset::AgentExecution.to_policy();

        // Use through the trait
        let provider: &dyn ReconcilePolicyProvider = &policy;
        assert_eq!(provider.broken_ast_behavior(), BrokenAstBehavior::Reject);
        assert_eq!(provider.formatting_policy(), FormattingPolicy::Strip);
        assert!(!provider.should_maintain_git_shadow());
        assert_eq!(provider.projection_mode(), ProjectionMode::Compact);
        assert_eq!(provider.validation_strictness(), ValidationLevel::Strict);
    }

    #[test]
    fn preset_serde_names() {
        assert_eq!(
            serde_json::to_string(&WorldPreset::KinNative).unwrap(),
            "\"kin_native\""
        );
        assert_eq!(
            serde_json::to_string(&WorldPreset::Brownfield).unwrap(),
            "\"brownfield\""
        );
        assert_eq!(
            serde_json::to_string(&WorldPreset::AgentExecution).unwrap(),
            "\"agent_execution\""
        );
    }

    #[test]
    fn broken_ast_behavior_serde() {
        assert_eq!(
            serde_json::to_string(&BrokenAstBehavior::Reject).unwrap(),
            "\"reject\""
        );
        assert_eq!(
            serde_json::to_string(&BrokenAstBehavior::FallbackToLkg).unwrap(),
            "\"fallback_to_lkg\""
        );
    }

    #[test]
    fn overrides_skip_none_in_json() {
        let overrides = PolicyOverrides {
            git_shadow: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_string(&overrides).unwrap();
        assert!(json.contains("git_shadow"));
        assert!(!json.contains("broken_ast_behavior"));
        assert!(!json.contains("formatting_policy"));
    }

    #[test]
    fn exact_directory_match() {
        let config = PresetConfig {
            preset: WorldPreset::Brownfield,
            overrides: PolicyOverrides::default(),
            directory_presets: {
                let mut map = HashMap::new();
                map.insert(
                    "ci".to_string(),
                    DirectoryPreset {
                        preset: Some(WorldPreset::KinNative),
                        overrides: PolicyOverrides::default(),
                    },
                );
                map
            },
        };

        // Exact match on the directory itself
        let policy = config.resolve_policy_for("ci");
        assert_eq!(policy, WorldPreset::KinNative.to_policy());
    }
}
