// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

pub mod assistant;
pub mod assistant_sync;
pub mod config;
pub mod error;
pub mod hooks;
pub mod init;
pub mod layout;
pub mod manifest;
pub mod resolver;
pub mod shims;
pub mod text_refs;
pub mod tree;

pub use assistant::{
    doctor, generate_assistant_prompt, generate_bootstrap_docs, generate_config_snippets,
    import_legacy_docs, install_adapter, list_adapters, resolve_actor_from_session,
    resolve_human_actor, write_config_snippets, AssistantAdapterConfig, AssistantKind,
    ConfigSnippet, DoctorReport, InstallResult, PromptMode,
};
pub use assistant_sync::{
    generate_managed_content, sync_all, sync_doc, ManagedDocConfig, ManagedDocTarget, RepoSummary,
    SyncMode, SyncResult,
};
pub use config::{
    ArtifactPolicyConfig, ExecutionPolicyConfig, ExternalToolExecutionPolicy, KinConfig,
    NonCodeArtifactPolicy, RemoteConfig, RemoteHostKind, RemoteRefConfig, RemoteTransportKind,
    WorldConfig, WorldPreset,
};
pub use error::{KinError, Result};
pub use hooks::{
    generate_claude_hooks, render_hooks_instructions, render_hooks_json, HookTemplate,
};
pub use init::{build_genesis_change, init, init_graph, InitResult};
pub use layout::KinLayout;
pub use manifest::KinManifest;
pub use resolver::{ImportResolver, PythonResolver, SymbolTable, TypeScriptResolver};
pub use text_refs::{find_text_references, TextReferenceMatch};
pub use tree::{build_file_tree, checkout_branch};

use kin_model::BranchName;

/// Repository mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoMode {
    /// Standard mode — source files live at repo root alongside `.kin/`.
    Compat,
    /// Native mode — repo root is a control surface, source files in `.kin/source-root/`.
    Native,
}

impl RepoMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compat => "compat",
            Self::Native => "native",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim() {
            "compat" => Some(Self::Compat),
            "native" => Some(Self::Native),
            _ => None,
        }
    }
}

impl std::fmt::Display for RepoMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Read the current repository mode from `.kin/mode`.
/// Returns `Compat` if the file doesn't exist.
pub fn read_repo_mode(layout: &KinLayout) -> RepoMode {
    let path = layout.mode_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => RepoMode::from_str(&content).unwrap_or(RepoMode::Compat),
        Err(_) => RepoMode::Compat,
    }
}

/// Write the repository mode to `.kin/mode`.
pub fn write_repo_mode(layout: &KinLayout, mode: RepoMode) -> Result<()> {
    std::fs::write(layout.mode_path(), mode.as_str())
        .map_err(|e| KinError::io(layout.mode_path(), e))
}

/// Return the effective source directory for materialization.
///
/// Checks `KIN_SOURCE_ROOT` env var first (used when source-root is relocated
/// outside the workspace, e.g. in benchmarks).  Otherwise falls back to
/// `.kin/source-root/` (native) or the working directory (compat).
pub fn source_dir(layout: &KinLayout) -> std::path::PathBuf {
    if let Ok(override_root) = std::env::var("KIN_SOURCE_ROOT") {
        let p = std::path::PathBuf::from(&override_root);
        if p.is_dir() {
            // Validate that the override path is within the workspace root
            // or is an ancestor of `.kin/`.
            let workspace_root = layout.working_dir();
            let kin_root = layout.root();
            let is_within_workspace = p.starts_with(workspace_root);
            let is_ancestor_of_kin = kin_root.starts_with(&p);
            if !is_within_workspace && !is_ancestor_of_kin {
                tracing::warn!(
                    override_path = %p.display(),
                    workspace = %workspace_root.display(),
                    "KIN_SOURCE_ROOT points outside the workspace — using it anyway for backward compatibility"
                );
            }
            return p;
        }
    }
    let mode = read_repo_mode(layout);
    match mode {
        RepoMode::Native => layout.source_root_dir(),
        RepoMode::Compat => layout.working_dir().to_path_buf(),
    }
}

/// Read the current branch name from `.kin/HEAD`.
pub fn read_current_branch(layout: &KinLayout) -> Result<BranchName> {
    let content = std::fs::read_to_string(layout.head_path())
        .map_err(|e| KinError::io(layout.head_path(), e))?;
    Ok(BranchName::new(content.trim()))
}

/// Write the current branch name to `.kin/HEAD`.
pub fn write_current_branch(layout: &KinLayout, name: &BranchName) -> Result<()> {
    std::fs::write(layout.head_path(), name.to_string())
        .map_err(|e| KinError::io(layout.head_path(), e))
}
