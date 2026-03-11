pub mod assistant;
pub mod assistant_sync;
pub mod config;
pub mod error;
pub mod hooks;
pub mod init;
pub mod layout;
pub mod manifest;
pub mod resolver;
pub mod tree;

pub use assistant::{
    doctor, generate_config_snippets, install_adapter, list_adapters, write_config_snippets,
    AssistantAdapterConfig, AssistantKind, ConfigSnippet, DoctorReport, InstallResult,
};
pub use assistant_sync::{
    generate_managed_content, sync_all, sync_doc, ManagedDocConfig, ManagedDocTarget, RepoSummary,
    SyncMode, SyncResult,
};
pub use config::KinConfig;
pub use hooks::{generate_claude_hooks, render_hooks_instructions, render_hooks_json, HookTemplate};
pub use error::{KinError, Result};
pub use init::{build_genesis_change, init, init_graph, InitResult};
pub use layout::KinLayout;
pub use manifest::KinManifest;
pub use resolver::{ImportResolver, PythonResolver, SymbolTable, TypeScriptResolver};
pub use tree::{build_file_tree, checkout_branch};

use kin_model::BranchName;

/// Read the current branch name from `.kin/HEAD`.
pub fn read_current_branch(layout: &KinLayout) -> Result<BranchName> {
    let content = std::fs::read_to_string(layout.head_path())
        .map_err(|e| KinError::io(&layout.head_path(), e))?;
    Ok(BranchName::new(content.trim()))
}

/// Write the current branch name to `.kin/HEAD`.
pub fn write_current_branch(layout: &KinLayout, name: &BranchName) -> Result<()> {
    std::fs::write(&layout.head_path(), name.to_string())
        .map_err(|e| KinError::io(&layout.head_path(), e))
}
