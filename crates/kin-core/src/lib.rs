// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod assistant;
pub mod assistant_sync;
pub mod behavior_env;
pub mod config;
pub mod dependencies;
pub mod diff;
pub mod disambiguation;
pub mod env_registry;
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
pub use tree::{
    build_file_tree, checkout_branch, materialize_source_entry, materialize_source_tree,
    prepare_source_tree, reconcile_source_tree, replace_source_tree, should_preserve_checkout_path,
    validate_portable_source_paths, validate_portable_source_symlink, validate_source_entry,
    validate_source_paths, validate_source_tree,
};

pub use diff::{compute_semantic_change_id, content_identity_from_deltas, whoami};
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
    use std::io::Write;

    let temporary = layout
        .root()
        .join(format!(".HEAD-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| KinError::io(&temporary, error))?;
    let write_result = file
        .write_all(name.to_string().as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| KinError::io(&temporary, error));
    if let Err(error) = write_result {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    #[cfg(windows)]
    let replace_result = replace_current_branch_windows(&temporary, &layout.head_path());
    #[cfg(not(windows))]
    let replace_result = std::fs::rename(&temporary, layout.head_path());
    if let Err(error) = replace_result {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(KinError::io(layout.head_path(), error));
    }
    file.sync_all()
        .map_err(|error| KinError::io(layout.head_path(), error))?;
    drop(file);
    #[cfg(unix)]
    {
        let directory = std::fs::File::open(layout.root())
            .map_err(|error| KinError::io(layout.root(), error))?;
        directory
            .sync_all()
            .map_err(|error| KinError::io(layout.root(), error))?;
    }
    Ok(())
}

/// Replace `.kin/HEAD` atomically on Windows even when the destination exists.
/// `std::fs::rename` maps to a non-replacing move there, so every checkout after
/// the first otherwise fails with `AlreadyExists`. `MoveFileExW` preserves the
/// same-volume atomic name switch and asks the OS to flush the rename metadata.
#[cfg(windows)]
fn replace_current_branch_windows(
    source: &std::path::Path,
    target: &std::path::Path,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let mut source_wide = source.as_os_str().encode_wide().collect::<Vec<_>>();
    source_wide.push(0);
    let mut target_wide = target.as_os_str().encode_wide().collect::<Vec<_>>();
    target_wide.push(0);
    if unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read the raw bytes of a blob from the layout's objects directory by its hash.
pub fn read_blob_from_layout(layout: &KinLayout, hash: &kin_model::Hash256) -> Option<Vec<u8>> {
    let store = kin_blobs::BlobStore::new(layout.objects_dir()).ok()?;
    store.read(hash).ok()
}

#[cfg(test)]
mod current_branch_tests {
    use super::*;

    #[test]
    fn current_branch_write_replaces_existing_head() {
        let root = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(root.path().join(".kin"));
        std::fs::create_dir_all(layout.root()).unwrap();
        std::fs::write(layout.head_path(), b"main").unwrap();

        write_current_branch(&layout, &BranchName::new("feature")).unwrap();
        write_current_branch(&layout, &BranchName::new("release")).unwrap();

        assert_eq!(read_current_branch(&layout).unwrap().to_string(), "release");
        assert_eq!(
            std::fs::read_dir(layout.root())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".HEAD-"))
                .count(),
            0
        );
    }
}
