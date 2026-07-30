// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Read-only access to the active repository-v6 authority.
//!
//! MCP handlers must not reconstruct refs, workspace state, aliases, or source
//! bytes from legacy sidecars or the working directory. Product dispatch binds
//! repository identity and a storage capability once at process/daemon startup,
//! then every handler reuses that retained capability. Reopening from a mutable
//! manifest or `.kin/kindb` path inside a request would bless namespace swaps
//! and let one daemon silently change which repository it serves.

use std::collections::BTreeSet;
use std::path::PathBuf;

use kin_db::{
    LocalFileBackend, PersistedRepositoryAuthority, RepositoryAuthorityManager,
    RepositoryAuthorityState,
};
use kin_model::{
    ExternalObjectKind, GitObjectId, RefName, RefTarget, RepositoryId, RepositoryRef,
    SemanticChangeId, WorkspaceId, WorkspaceState,
};

use crate::error::{McpError, Result};

pub use kin_core::LocalRepositoryAuthorityBinding;

/// Read repository-v6 authority metadata under a name that cannot be mistaken
/// for filesystem metadata.
///
/// `AuthorityReadLease` exposes this state as `metadata()`, which reads at a
/// call site exactly like `std::fs::Metadata` access and trips the zero
/// file-search guard's filesystem heuristic. The guard is deliberately blunt,
/// so the fix is to make authority reads unmistakable rather than to teach the
/// guard an exception that a real filesystem probe could later hide behind.
pub(crate) trait RepositoryAuthorityMetadata {
    fn authority_metadata(&self) -> &PersistedRepositoryAuthority;
}

impl RepositoryAuthorityMetadata for RepositoryAuthorityState {
    fn authority_metadata(&self) -> &PersistedRepositoryAuthority {
        self.snapshot()
            .repository_authority
            .as_ref()
            .expect("repository authority lease always carries authority metadata")
    }
}

/// Discover and pin a repository once for the explicit offline stdio loop.
///
/// A process launched outside a Kin repository has no binding; handlers that
/// require exact repository authority will then fail loudly. An invalid
/// repository that *is* discovered remains a startup error.
pub(crate) fn discover_for_process() -> Result<Option<LocalRepositoryAuthorityBinding>> {
    let start = std::env::var_os("KIN_SOURCE_ROOT")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)?;
    let Some(layout) = kin_core::KinLayout::discover(&start) else {
        return Ok(None);
    };
    LocalRepositoryAuthorityBinding::from_layout(&layout)
        .map(Some)
        .map_err(|error| McpError::Context(format!("graph authority gap: {error}")))
}

pub(crate) struct ActiveRepositoryAuthority {
    manager: RepositoryAuthorityManager<LocalFileBackend>,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
}

/// One instant of workspace authority: the exact graph-owned tree, its identity
/// and generation, and the committed change its base resolves to.
///
/// Every field is read out of a single `AuthorityReadLease`, which is an `Arc`
/// snapshot of the whole published authority state, so these facts describe one
/// generation by construction. That is the property a source read needs and the
/// reason this type exists: calling `workspace()` for the tree and then a second
/// accessor for the change id takes two independent snapshots, and a concurrent
/// admission between them pairs one generation's bytes with another generation's
/// provenance. Nothing serializes those two reads, so the only fix is to stop
/// taking two.
pub(crate) struct WorkspaceReadSample {
    pub workspace: WorkspaceState,
    /// The committed change `workspace.base_target` resolves to, resolved
    /// against the same snapshot the workspace was read from.
    pub base_change_id: SemanticChangeId,
}

impl ActiveRepositoryAuthority {
    pub(crate) fn open(binding: &LocalRepositoryAuthorityBinding) -> Result<Self> {
        let manager = binding.open_manager().map_err(|error| {
            McpError::Context(format!(
                "graph authority gap: cannot open retained repository authority: {error}"
            ))
        })?;
        Ok(Self {
            manager,
            repository_id: binding.repository_id().clone(),
            workspace_id: binding.workspace_id(),
        })
    }

    pub(crate) fn workspace(&self) -> Result<WorkspaceState> {
        let lease = self.manager.read_authority();
        self.workspace_in(lease.authority_metadata())
    }

    /// One coherent instant of workspace authority.
    ///
    /// Prefer this over `workspace()` plus a separate change-id accessor
    /// anywhere both the tree and its provenance feed one answer: a single
    /// snapshot cannot straddle an admission, two snapshots can. See
    /// [`WorkspaceReadSample`].
    pub(crate) fn workspace_sample(&self) -> Result<WorkspaceReadSample> {
        let lease = self.manager.read_authority();
        let metadata = lease.authority_metadata();
        let workspace = self.workspace_in(metadata)?;
        let target = workspace.base_target.clone().ok_or_else(|| {
            McpError::Context(format!(
                "graph authority gap: workspace {} has an unborn head",
                workspace.workspace_id
            ))
        })?;
        let base_change_id = self.resolve_target_in(metadata, target)?;
        Ok(WorkspaceReadSample {
            workspace,
            base_change_id,
        })
    }

    fn workspace_in(&self, metadata: &PersistedRepositoryAuthority) -> Result<WorkspaceState> {
        metadata
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == self.workspace_id)
            .cloned()
            .ok_or_else(|| {
                McpError::Context(format!(
                    "graph authority gap: repository {} has no workspace {}",
                    self.repository_id, self.workspace_id
                ))
            })
    }

    pub(crate) fn repository_ref(&self, name: &RefName) -> Option<RepositoryRef> {
        self.manager
            .read_authority()
            .authority_metadata()
            .ref_state
            .refs
            .iter()
            .find(|repository_ref| &repository_ref.name == name)
            .cloned()
    }

    pub(crate) fn repository_refs(&self) -> Vec<RepositoryRef> {
        self.manager
            .read_authority()
            .authority_metadata()
            .ref_state
            .refs
            .clone()
    }

    pub(crate) fn default_ref(&self) -> Option<RefName> {
        self.manager
            .read_authority()
            .authority_metadata()
            .ref_state
            .default_ref
            .clone()
    }

    pub(crate) fn resolve_target(&self, target: &RefTarget) -> Result<SemanticChangeId> {
        let lease = self.manager.read_authority();
        self.resolve_target_in(lease.authority_metadata(), target.clone())
    }

    /// Resolve a ref target against ONE authority snapshot.
    ///
    /// Symbolic hops and external-commit aliases are followed inside the same
    /// `metadata` the caller sampled, so a chain can never be walked across two
    /// generations of ref state and land on a change that no single generation
    /// pointed at.
    fn resolve_target_in(
        &self,
        metadata: &PersistedRepositoryAuthority,
        target: RefTarget,
    ) -> Result<SemanticChangeId> {
        let mut target = target;
        let mut visited = BTreeSet::new();
        loop {
            match target {
                RefTarget::Change { change_id } => return Ok(change_id),
                RefTarget::ExternalObject { object } => {
                    if object.kind != ExternalObjectKind::Commit {
                        return Err(McpError::Context(format!(
                            "graph authority gap: external ref target {} is a {:?}, not a commit",
                            object.oid, object.kind
                        )));
                    }
                    return metadata
                        .aliases
                        .iter()
                        .find(|alias| alias.oid == object.oid)
                        .map(|alias| alias.change_id)
                        .ok_or_else(|| {
                            McpError::Context(format!(
                                "graph authority gap: external commit {} has no repository alias",
                                object.oid
                            ))
                        });
                }
                RefTarget::Symbolic { target: name } => {
                    if !visited.insert(name.clone()) {
                        return Err(McpError::Context(format!(
                            "graph authority gap: symbolic repository ref cycle reaches {name}"
                        )));
                    }
                    target = metadata
                        .ref_state
                        .refs
                        .iter()
                        .find(|repository_ref| repository_ref.name == name)
                        .map(|repository_ref| repository_ref.target.clone())
                        .ok_or_else(|| {
                            McpError::Context(format!(
                                "graph authority gap: symbolic repository ref {name} is absent"
                            ))
                        })?;
                }
            }
        }
    }

    pub(crate) fn resolve_named_ref(&self, name: &RefName) -> Result<SemanticChangeId> {
        let repository_ref = self.repository_ref(name).ok_or_else(|| {
            McpError::InvalidParams(format!("repository ref '{name}' was not found"))
        })?;
        self.resolve_target(&repository_ref.target)
    }

    pub(crate) fn resolve_git_oid(&self, oid: GitObjectId) -> Result<SemanticChangeId> {
        self.manager
            .read_authority()
            .authority_metadata()
            .aliases
            .iter()
            .find(|alias| alias.oid == oid)
            .map(|alias| alias.change_id)
            .ok_or_else(|| {
                McpError::InvalidParams(format!(
                    "Git commit '{oid}' has no imported repository alias"
                ))
            })
    }

    pub(crate) fn load_source_blob(&self, digest: kin_model::Hash256) -> Result<Vec<u8>> {
        self.manager
            .load_source_blob(digest)
            .map_err(|error| {
                McpError::Context(format!(
                    "graph authority gap: cannot load immutable source blob {digest}: {error}"
                ))
            })?
            .ok_or_else(|| {
                McpError::Context(format!(
                    "graph authority gap: immutable source blob {digest} is absent"
                ))
            })
    }
}

pub(crate) fn parse_branch_ref(value: &str) -> Result<RefName> {
    if value.starts_with("refs/") {
        RefName::from_utf8(value).map_err(|error| {
            McpError::InvalidParams(format!("invalid fully-qualified repository ref: {error}"))
        })
    } else {
        RefName::branch(value.as_bytes())
            .map_err(|error| McpError::InvalidParams(format!("invalid branch name: {error}")))
    }
}

pub(crate) fn parse_git_object_id(value: &str) -> Result<GitObjectId> {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(McpError::InvalidParams(format!(
            "invalid Git object ID '{value}': expected hexadecimal bytes"
        )));
    }
    let bytes = hex::decode(value).map_err(|error| {
        McpError::InvalidParams(format!("invalid Git object ID '{value}': {error}"))
    })?;
    match bytes.len() {
        20 => Ok(GitObjectId::sha1(
            bytes
                .try_into()
                .expect("20-byte Git object IDs convert to SHA-1 arrays"),
        )),
        32 => {
            Ok(GitObjectId::sha256(bytes.try_into().expect(
                "32-byte Git object IDs convert to SHA-256 arrays",
            )))
        }
        length => Err(McpError::InvalidParams(format!(
            "invalid Git object ID '{value}': expected 20 or 32 bytes, found {length}"
        ))),
    }
}
