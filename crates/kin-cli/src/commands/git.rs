// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository-v6 projection into a new Git repository.
//!
//! Git is an interoperability projection, never an authority fallback. The
//! command captures one immutable repository-authority lease, loads every
//! object body from repository-owned source CAS, and delegates publication to
//! `kin-git`'s staged, self-verifying exporter. The working directory and any
//! pre-existing Git object store are not consulted.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use kin_db::RepositoryAuthorityState;
use kin_model::{
    GitObjectBodyLoader, Hash256, RepositoryId, RootBundle, WorkspaceId, WorkspaceState,
};

use super::repository_authority::ActiveRepositoryAuthority;

/// One coherent repository-v6 export input.
///
/// All graph, ref, alias, workspace-head, and Git-authority state is cloned
/// from one lease.
pub(crate) struct AuthorityExportSnapshot {
    pub(crate) roots: RootBundle,
    pub(crate) workspace: WorkspaceState,
    pub(crate) plan: kin_git::RepositoryGitExportPlan,
}

pub(crate) struct RepositorySource<'a> {
    authority: &'a ActiveRepositoryAuthority,
}

impl<'a> RepositorySource<'a> {
    pub(crate) fn new(authority: &'a ActiveRepositoryAuthority) -> Self {
        Self { authority }
    }
}

impl GitObjectBodyLoader for RepositorySource<'_> {
    type Error = String;

    fn load_body(
        &mut self,
        body_hash: &Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        self.authority
            .manager()
            .load_source_blob(*body_hash)
            .map_err(|error| error.to_string())
    }
}

pub(crate) fn capture_export_snapshot(
    authority: &ActiveRepositoryAuthority,
) -> Result<AuthorityExportSnapshot> {
    let lease = authority.manager().read_authority();
    capture_export_snapshot_from_state(&authority.repository_id, &authority.workspace_id, &lease)
}

/// Capture a coherent export input from an already-held authority state.
///
/// Eject uses this with the freshly reloaded state carried by the exclusive
/// local freeze rather than opening a second lease after the writer lock has
/// been acquired.
pub(crate) fn capture_export_snapshot_from_state(
    repository_id: &RepositoryId,
    workspace_id: &WorkspaceId,
    state: &RepositoryAuthorityState,
) -> Result<AuthorityExportSnapshot> {
    let metadata = state.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| &workspace.workspace_id == workspace_id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in its authority",
                repository_id,
                workspace_id
            )
        })?;
    let plan = kin_git::RepositoryGitExportPlan {
        repository_id: metadata.repository_id.clone(),
        changes: state.snapshot().changes.values().cloned().collect(),
        aliases: metadata.aliases.clone(),
        refs: metadata.ref_state.clone(),
        head: workspace.head.clone(),
        git_authority: metadata.git_external_authority.clone(),
    };

    Ok(AuthorityExportSnapshot {
        roots: state.roots().clone(),
        workspace,
        plan,
    })
}

/// Project repository-v6 authority into a new bare Git repository.
pub fn export(output: PathBuf) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let layout = crate::commands::require_repository_layout_at(&cwd)?;
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    let output = validate_export_destination(&layout, &cwd, &output)?;
    let authority = ActiveRepositoryAuthority::open(&binding)?;
    let captured = capture_export_snapshot(&authority)?;
    let mut source = RepositorySource::new(&authority);
    let result = kin_git::export_repository_to_git(&captured.plan, &mut source, &output)
        .context("project repository-v6 authority to Git")?;

    // A read lease remains immutable, but a distinct writer can publish a new
    // generation while export is running. Report the exact generation that
    // produced this repository instead of implying it is an ambient latest
    // view.
    println!(
        "Exported repository {} authority generation {} to {}",
        captured.plan.repository_id,
        captured.roots.generation,
        result.git_repo_path.display()
    );
    println!(
        "{} imported commits reused, {} native commits written, {} refs written",
        result.imported_commits_reused, result.native_commits_written, result.refs_written
    );
    Ok(())
}

fn validate_export_destination(
    layout: &kin_core::KinLayout,
    cwd: &Path,
    requested: &Path,
) -> Result<PathBuf> {
    if requested.as_os_str().is_empty() {
        bail!("Git export destination cannot be empty");
    }
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        cwd.join(requested)
    };
    let name = requested
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("Git export destination must name a repository directory")
        })?;
    let parent = requested.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "Git export destination {} has no parent",
            requested.display()
        )
    })?;
    let canonical_parent = parent.canonicalize().with_context(|| {
        format!(
            "Git export destination parent {} must already exist",
            parent.display()
        )
    })?;
    let destination = canonical_parent.join(name);
    let repository_root = layout
        .working_dir()
        .canonicalize()
        .context("resolve Kin repository root before Git export")?;
    if destination.starts_with(&repository_root) {
        bail!(
            "Git export destination {} is inside the Kin working repository; \
             choose a new sibling path or use `kin eject` to leave Kin in place",
            destination.display()
        );
    }
    if destination.exists() {
        bail!(
            "Git export destination {} already exists; refusing to merge with ambient Git state",
            destination.display()
        );
    }
    Ok(destination)
}
