// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-private access to the local repository-v6 authority pinned at startup.

use std::sync::atomic::Ordering;

use anyhow::{bail, Result};
use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{RepositoryId, RootBundle, WorkspaceId};

use crate::error::DaemonError;
use crate::state::DaemonState;

/// Copyable capability for opening the local repository authority that this
/// daemon validated at startup.
///
/// Keeping the original `LocalFileBackend` alive is security-significant:
/// KinDB pins the storage root's device/inode identity on that backend. A new
/// path-based backend would accept an identically copied replacement root.
#[derive(Clone)]
pub(crate) struct LocalRepositoryAuthorityContext {
    binding: kin_core::LocalRepositoryAuthorityBinding,
}

impl LocalRepositoryAuthorityContext {
    pub(crate) fn from_state(state: &DaemonState) -> std::result::Result<Self, DaemonError> {
        state
            .local_repository_authority_binding()
            .map(|binding| Self { binding })
    }

    #[cfg(test)]
    pub(crate) fn from_layout_for_test(layout: &kin_core::KinLayout) -> Result<Self> {
        Ok(Self {
            binding: kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)?,
        })
    }

    pub(crate) fn repository_id(&self) -> &RepositoryId {
        self.binding.repository_id()
    }

    pub(crate) fn workspace_id(&self) -> WorkspaceId {
        self.binding.workspace_id()
    }

    pub(crate) fn open(
        &self,
    ) -> std::result::Result<RepositoryAuthorityManager<LocalFileBackend>, kin_db::KinDbError> {
        self.binding.open_manager()
    }
}

/// Local repository authority bound to the identities the daemon validated at
/// startup.
///
/// Command handlers must use this boundary instead of rediscovering repository
/// or workspace identity from mutable manifests.
pub(crate) struct ActiveLocalRepositoryAuthority {
    pub(crate) manager: RepositoryAuthorityManager<LocalFileBackend>,
    pub(crate) repository_id: RepositoryId,
    pub(crate) workspace_id: WorkspaceId,
}

impl ActiveLocalRepositoryAuthority {
    pub(crate) fn open(state: &DaemonState) -> Result<Self> {
        let context = LocalRepositoryAuthorityContext::from_state(state)?;
        let manager = context.open().map_err(|error| {
            anyhow::anyhow!(
                "open repository-v6 authority through startup-pinned storage capability: {error}"
            )
        })?;
        Ok(Self {
            manager,
            repository_id: context.repository_id().clone(),
            workspace_id: context.workspace_id(),
        })
    }
}

/// Refuse a fresh repository mutation unless the daemon's complete derived
/// workspace still names the exact authority lease used to plan it.
pub(crate) fn require_fresh_daemon_workspace(
    state: &DaemonState,
    roots: &RootBundle,
    workspace_graph: &kin_db::GraphSnapshot,
    operation: &str,
) -> Result<()> {
    let daemon_generation = state.snapshot_generation.load(Ordering::SeqCst);
    if daemon_generation != roots.generation {
        bail!(
            "daemon repository cursor is at generation {daemon_generation}, but {operation} \
             authority is at generation {}; reopen from repository authority before mutating",
            roots.generation
        );
    }
    let live = state.graph.to_snapshot();
    if live.resolved_tree != workspace_graph.resolved_tree
        || live.entities != workspace_graph.entities
        || live.relations != workspace_graph.relations
    {
        bail!(
            "daemon graph does not match the exact repository workspace authority; reopen before \
             {operation}"
        );
    }
    Ok(())
}
