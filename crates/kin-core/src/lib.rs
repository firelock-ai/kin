// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod assistant;
pub mod assistant_sync;
pub mod config;
pub mod dependencies;
pub mod diff;
pub mod disambiguation;
pub mod error;
pub mod hooks;
pub mod init;
pub mod layout;
pub mod manifest;
pub mod ranking;
pub mod ref_view;
pub mod registry;
pub mod resolver;
pub mod shims;
pub mod sync_state;
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
    ExecutionPolicyConfig, ExternalToolExecutionPolicy, KinConfig, RemoteConfig, RemoteHostKind,
    RemoteRefConfig, RemoteTransportKind, WorldConfig, WorldPreset,
};
pub use error::{KinError, Result};
pub use hooks::{
    generate_claude_hooks, render_hooks_instructions, render_hooks_json, HookTemplate,
};
pub use init::{build_genesis_change, init, init_graph, InitResult};
pub use layout::KinLayout;
pub use manifest::KinManifest;
pub use resolver::{ImportResolver, PythonResolver, SymbolTable, TypeScriptResolver};
pub use sync_state::SyncStateStore;
pub use text_refs::{
    find_text_reference_occurrences, find_text_references, TextReferenceMatch,
    TextReferenceOccurrence, TextReferenceOccurrenceMatch,
};
pub use tree::{build_file_tree, checkout_branch};

pub use diff::{compute_change_id, whoami};
pub use disambiguation::{fallback_leaf_trace_matches, query_trace_matches};
pub use ranking::{
    normalize_symbol_hint, normalize_trace_name, qualifier_hint_from_query, select_best_match,
};
pub use ref_view::{
    build_change_oid_cache, build_graph_at_git_ref_with_repo, build_graph_at_ref,
    build_graph_at_ref_with_repo, collect_changes_at_ref, filter_vector_results_to_scope,
    ChangeOidCache,
};

use kin_model::BranchName;

/// Return the effective source directory for materialization.
///
/// Checks `KIN_SOURCE_ROOT` env var first (used when source-root is relocated
/// outside the workspace, e.g. in benchmarks). Otherwise returns the working
/// directory (repo root alongside `.kin/`).
///
/// There is one mode: Kin. Source files live at the repo root. The graph owns
/// truth; the filesystem is a projection. No compat mode, no source-root.
pub fn source_dir(layout: &KinLayout) -> std::path::PathBuf {
    if let Ok(override_root) = std::env::var("KIN_SOURCE_ROOT") {
        let p = std::path::PathBuf::from(&override_root);
        if p.is_dir() {
            return p;
        }
    }
    layout.working_dir().to_path_buf()
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

/// Read the raw bytes of a blob from the layout's objects directory by its hash.
pub fn read_blob_from_layout(layout: &KinLayout, hash: &kin_model::Hash256) -> Option<Vec<u8>> {
    let store = kin_blobs::BlobStore::new(layout.objects_dir()).ok()?;
    store.read(hash).ok()
}
