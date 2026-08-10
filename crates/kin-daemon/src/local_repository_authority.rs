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

    pub(crate) fn revalidate_pinned_namespace(
        &self,
    ) -> std::result::Result<(), kin_core::PinnedNamespaceRefusal> {
        self.binding.revalidate_pinned_namespace()
    }
}

/// Why a command refused to bind this daemon's local repository authority.
///
/// Command boundaries answer an identity refusal with a typed conflict rather
/// than a generic internal error: the request is coherent, but the storage
/// namespace this daemon pinned is no longer the one on disk, so there is no
/// authority left to answer from.
pub(crate) enum RepositoryAuthorityBindRefusal {
    /// This daemon never completed a startup repository binding.
    Unbound(DaemonError),
    /// The retained capability no longer reaches the exact per-repository
    /// namespace this daemon pinned: replaced at the same ambient path,
    /// detached, or a store that does not hold this repository.
    Identity(kin_db::KinDbError),
    /// The pinned namespace is intact but its authority could not be opened, or
    /// the revalidation itself reached no verdict about identity. Neither says
    /// the repository was replaced, so neither answers with a conflict.
    Unavailable(kin_db::KinDbError),
}

impl RepositoryAuthorityBindRefusal {
    pub(crate) fn is_identity_refusal(&self) -> bool {
        matches!(self, Self::Identity(_))
    }

    pub(crate) fn into_error(self) -> anyhow::Error {
        match self {
            Self::Unbound(error) => anyhow::Error::new(error),
            Self::Identity(error) => anyhow::anyhow!(
                "refusing repository-v6 authority: the storage namespace this daemon pinned at \
                 startup is no longer the one at that path: {error}"
            ),
            Self::Unavailable(error) => anyhow::anyhow!(
                "open repository-v6 authority through startup-pinned storage capability: {error}"
            ),
        }
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
    /// Bind the startup-pinned authority, revalidating the retained
    /// per-repository namespace identity before any planning reads it.
    ///
    /// The revalidation is deliberately ahead of the authority open so a
    /// replaced or detached namespace is named as such, instead of surfacing as
    /// whatever the authority decode happens to fail on. It reads namespace
    /// identity from metadata alone and classifies its own refusal, so a fault
    /// that says nothing about identity stays internal and the bind still pays
    /// exactly one authority load and one exclusive lock, in the open below.
    /// That same open also refuses a retained namespace whose persisted
    /// authority record is absent rather than accepting a fresh generation
    /// zero in its place.
    pub(crate) fn open_bound(
        state: &DaemonState,
    ) -> std::result::Result<Self, RepositoryAuthorityBindRefusal> {
        let context = LocalRepositoryAuthorityContext::from_state(state)
            .map_err(RepositoryAuthorityBindRefusal::Unbound)?;
        context
            .revalidate_pinned_namespace()
            .map_err(|refusal| match refusal {
                kin_core::PinnedNamespaceRefusal::Identity(error) => {
                    RepositoryAuthorityBindRefusal::Identity(error)
                }
                kin_core::PinnedNamespaceRefusal::Unavailable(error) => {
                    RepositoryAuthorityBindRefusal::Unavailable(error)
                }
            })?;
        let manager = context
            .open()
            .map_err(RepositoryAuthorityBindRefusal::Unavailable)?;
        Ok(Self {
            manager,
            repository_id: context.repository_id().clone(),
            workspace_id: context.workspace_id(),
        })
    }

    /// Bind for assertions that only need the refusal text. Command paths must
    /// use [`Self::open_bound`] so they can answer with a typed status.
    #[cfg(test)]
    pub(crate) fn open(state: &DaemonState) -> Result<Self> {
        Self::open_bound(state).map_err(RepositoryAuthorityBindRefusal::into_error)
    }
}

/// Refuse a fresh repository mutation unless the daemon's derived workspace is
/// still a faithful view of the exact authority lease used to plan it.
///
/// The daemon query graph is a derived view that legitimately runs ahead of
/// workspace authority. Parser reconciliation and the asynchronous LSP
/// enrichment worker publish semantic facets into it continuously, and those
/// facets cross the repository-v6 compare-and-swap only when a change is
/// committed. Demanding exact equality here therefore refuses every authority
/// command that follows any enrichment tick, which wedges routine sessions
/// rather than protecting them.
///
/// What must still hold is narrower and is enforced below: the daemon is at the
/// same authority generation, it holds no exact tree state authority has not
/// admitted, and it has neither dropped nor rewritten any entity or relation
/// that authority owns. Because a derived lead is permitted, every caller must
/// plan its daemon-side transition from the live graph rather than reusing the
/// authority-side delta: repository commands do that through
/// [`plan_daemon_semantic_delta`], and the exact MCP commit path does it through
/// its own post-commit live-to-authority correction.
pub(crate) fn require_fresh_daemon_workspace(
    state: &DaemonState,
    roots: &RootBundle,
    workspace_graph: &kin_db::GraphSnapshot,
    operation: &str,
) -> Result<()> {
    let daemon_generation = state.snapshot_generation.load(Ordering::SeqCst);
    if daemon_generation != roots.generation {
        bail!(
            "daemon repository cursor is at generation {daemon_generation}, but the authority for \
             {operation} is at generation {}; reopen from repository authority before mutating",
            roots.generation
        );
    }
    let live = state.graph.to_snapshot();
    if live.resolved_tree != workspace_graph.resolved_tree {
        bail!(
            "daemon exact tree does not match the repository workspace authority; reopen before \
             {operation}"
        );
    }
    if let Some(divergence) = authority_semantics_divergence(&live, workspace_graph) {
        bail!(
            "daemon graph no longer holds the repository workspace authority it was planned \
             against ({divergence}); reopen before {operation}"
        );
    }
    Ok(())
}

/// Describe the first authority-owned entity or relation the daemon graph has
/// dropped, or `None` when authority is still fully retained.
///
/// A derived view may hold more than authority owns, and it may hold a richer
/// value for something authority owns. It may never hold less: a dropped entity
/// or relation means the daemon is answering from something other than graph
/// truth, and no derived writer produces that.
///
/// A rewrite is deliberately not divergence. Parser reconciliation and the
/// asynchronous LSP enrichment worker publish semantic facets onto existing
/// authority-owned entities continuously and outside the coordination gate, so
/// treating a rewritten value as divergence refuses every commit that follows
/// any enrichment tick. That is the same unachievable invariant the equality
/// check above was removed for, reintroduced one level down at entity
/// granularity, and it fails the same way: a caller told to "re-send this
/// commit unchanged once the daemon is reading current repository authority"
/// races the worker and loses again, naming a different rewritten entity each
/// attempt, until the daemon is recycled.
///
/// Tolerating the rewrite is safe because a derived lead cannot reach
/// publication. [`crate::mcp_commit`] builds its prospective graph from the
/// authority workspace snapshot and applies only the staged operations, so what
/// the live graph holds never enters the committed change. Staleness, the
/// failure this check is sometimes assumed to catch, is caught before it by the
/// generation binding above: a daemon that missed an authority move fails there
/// with both generations named. After the commit the live graph is corrected
/// onto authority and verified, which is where a genuinely corrupt derived
/// value is caught.
fn authority_semantics_divergence(
    live: &kin_db::GraphSnapshot,
    authority: &kin_db::GraphSnapshot,
) -> Option<String> {
    for entity_id in authority.entities.keys() {
        if !live.entities.contains_key(entity_id) {
            return Some(format!("entity {entity_id} is missing"));
        }
    }
    for relation_id in authority.relations.keys() {
        if !live.relations.contains_key(relation_id) {
            return Some(format!("relation {relation_id} is missing"));
        }
    }
    None
}

/// Plan the daemon-side semantic transition of one repository command from the
/// live query graph.
///
/// The authority-side delta of the same command is planned from the workspace
/// lease. These are deliberately two different deltas over the same transition:
/// the live graph carries derived enrichment that has not crossed the
/// compare-and-swap, so reusing the authority delta would leave that enrichment
/// installed and land the daemon on a graph that is not the exact target.
pub(crate) fn plan_daemon_semantic_delta(
    state: &DaemonState,
    target_entities: &std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    target_relations: &std::collections::HashMap<kin_model::RelationId, kin_model::Relation>,
) -> Result<kin_model::WorkspaceSemanticDelta> {
    let live = state.graph.to_snapshot();
    kin_core::diff_workspace_semantics(
        &live.entities,
        &live.relations,
        target_entities,
        target_relations,
    )
    .map_err(Into::into)
}
