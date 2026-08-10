// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Coherent read access to the active repository-v6 authority.
//!
//! CLI and daemon command helpers use this boundary instead of reconstructing
//! refs, workspace state, aliases, or source bytes from legacy sidecars, Git,
//! or the working directory.

use anyhow::{anyhow, Context, Result};
use kin_db::{
    AuthorityPayloadStats, LocalFileBackend, RepositoryAuthorityManager, RepositoryAuthorityState,
};
use kin_model::{
    GitObjectId, RefName, RefTarget, RepositoryId, RootBundle, SemanticChangeId, WorkspaceId,
    WorkspaceState,
};

pub struct ActiveRepositoryAuthority {
    manager: RepositoryAuthorityManager<LocalFileBackend>,
    payload_stats: Option<AuthorityPayloadStats>,
    pub(crate) repository_id: RepositoryId,
    pub(crate) workspace_id: WorkspaceId,
}

thread_local! {
    static REPOSITORY_AUTHORITY_OPENS_ON_THREAD: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

/// Repository-authority opens this crate's wrapper has performed ON THE CALLING
/// THREAD.
///
/// An open decodes the persisted snapshot and re-verifies every persisted body
/// against its content address, so its cost is a property of the store rather
/// than of the request. That makes the COUNT, not the wall clock, the honest
/// thing for a test to bound: a helper that opens once per item stays O(items)
/// here no matter how small the fixture is, where a timing assertion on a small
/// fixture passes with the defect present.
///
/// Per-thread rather than per-process because test binaries run in parallel and
/// a sibling test that projects a body would otherwise land in the same counter.
/// The caller must keep the measured section on one thread; a section that hands
/// its work to a worker reads zero, which fails an `== 1` bound loudly rather
/// than passing it silently.
pub fn repository_authority_opens_on_this_thread() -> u64 {
    REPOSITORY_AUTHORITY_OPENS_ON_THREAD.with(std::cell::Cell::get)
}

/// The repository authority one command reads at, and who paid for the open.
///
/// The same contract kin-mcp's `RequestRepositoryAuthority` states for the MCP
/// query tools, for the commands that read source through *this* crate's
/// wrapper. A one-shot CLI invocation has nobody to share an open with and opens
/// for itself, which is what every command helper did before this type existed.
/// A long-lived daemon does: it resolves one open per durable publication and
/// hands the same authority to every request reading at that publication.
///
/// Both arms answer from an open that passed KinDB's complete open-time
/// validation. There is no arm that produces authority which skipped it, and
/// reuse can only hand back the result of a validation that already ran over
/// these exact durable bytes. What a server must get right is not WHETHER the
/// authority it shares was validated but WHICH publication it was validated at;
/// see [`Self::shared`].
#[derive(Clone)]
pub struct RequestRepositoryAuthority {
    binding: kin_core::LocalRepositoryAuthorityBinding,
    shared: Option<SharedAuthorityResolver>,
}

/// A server's promise to produce authority for the publication a request reads
/// at, run only when a command actually reaches a source read.
pub type SharedAuthorityResolver =
    std::sync::Arc<dyn Fn() -> Result<std::sync::Arc<ActiveRepositoryAuthority>> + Send + Sync>;

impl RequestRepositoryAuthority {
    /// Authority this command opens for itself.
    pub fn pinned(binding: kin_core::LocalRepositoryAuthorityBinding) -> Self {
        Self {
            binding,
            shared: None,
        }
    }

    /// Authority a server resolves for the publication this request reads at.
    ///
    /// The server owns the freshness argument, and it is the whole of what this
    /// type cannot check for itself. Each call to the resolver must return an
    /// authority opened at a durable publication the server confirmed is still
    /// the one local storage holds, with that confirmation read BEFORE the open
    /// it labels rather than after. A label taken afterwards can name a
    /// publication that landed during the load, which marks older bytes as
    /// current and serves them past the commit that replaced them.
    pub fn shared(
        binding: kin_core::LocalRepositoryAuthorityBinding,
        resolve: SharedAuthorityResolver,
    ) -> Self {
        Self {
            binding,
            shared: Some(resolve),
        }
    }

    /// The startup-pinned identity and storage capability behind this authority,
    /// for the surfaces that still take a binding.
    pub fn binding(&self) -> &kin_core::LocalRepositoryAuthorityBinding {
        &self.binding
    }

    /// The open authority to read this command from.
    ///
    /// Reuses the caller's open when there is one, and otherwise performs the
    /// full validating open. Read paths call this rather than
    /// [`ActiveRepositoryAuthority::open`] so a server's shared open is not
    /// silently bypassed by one of them.
    ///
    /// A helper that resolves per item — the batched source tools resolve once
    /// per entity — costs one open for the whole batch on the shared arm and one
    /// per item on the pinned arm, which is exactly the one-shot behavior that
    /// arm is for.
    pub(crate) fn open(&self) -> Result<std::sync::Arc<ActiveRepositoryAuthority>> {
        match &self.shared {
            Some(resolve) => resolve(),
            None => ActiveRepositoryAuthority::open(&self.binding).map(std::sync::Arc::new),
        }
    }
}

impl ActiveRepositoryAuthority {
    /// Open the authority from durable storage.
    ///
    /// This re-verifies every persisted body against its content address, so it
    /// costs whatever the whole store is worth rather than whatever the caller
    /// asked for. `pub` so a long-lived server can pay for one open and hand it
    /// to the requests that read at that publication, through
    /// [`RequestRepositoryAuthority::shared`].
    pub fn open(binding: &kin_core::LocalRepositoryAuthorityBinding) -> Result<Self> {
        REPOSITORY_AUTHORITY_OPENS_ON_THREAD.with(|opens| opens.set(opens.get() + 1));
        let repository_id = binding.repository_id().clone();
        let workspace_id = binding.workspace_id();
        let (manager, payload_stats) = binding
            .open_manager_with_payload_stats()
            .context("open repository-v6 authority through retained local binding")?;

        Ok(Self {
            manager,
            payload_stats,
            repository_id,
            workspace_id,
        })
    }

    pub(crate) fn manager(&self) -> &RepositoryAuthorityManager<LocalFileBackend> {
        &self.manager
    }

    /// Payload receipt produced by the same recovery that built this manager.
    ///
    /// `None` only where no persisted authority existed and generation zero was
    /// built in memory. It never becomes stale, because it describes the bytes
    /// this open read rather than the repository's current size.
    pub(crate) fn payload_stats(&self) -> Option<AuthorityPayloadStats> {
        self.payload_stats
    }

    pub(crate) fn workspace(&self) -> Result<WorkspaceState> {
        self.workspace_with_roots().map(|(workspace, _)| workspace)
    }

    pub(crate) fn workspace_with_roots(&self) -> Result<(WorkspaceState, RootBundle)> {
        let lease = self.manager.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == self.workspace_id)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "repository {} has no workspace {} in repository-v6 authority",
                    self.repository_id,
                    self.workspace_id
                )
            })?;
        Ok((workspace, lease.roots().clone()))
    }

    pub(crate) fn resolve_named_ref(&self, name: &RefName) -> Result<SemanticChangeId> {
        let lease = self.manager.read_authority();
        let target = lease
            .resolve_ref_target(name)
            .with_context(|| format!("resolve repository ref '{name}'"))?
            .ok_or_else(|| anyhow!("repository ref '{name}' was not found"))?;
        lease
            .resolve_target_change_id(&target)
            .with_context(|| format!("resolve repository ref '{name}' semantic target"))
    }

    pub(crate) fn current_change_id(&self) -> Result<Option<SemanticChangeId>> {
        let lease = self.manager.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == self.workspace_id)
            .ok_or_else(|| {
                anyhow!(
                    "repository {} has no workspace {} in repository-v6 authority",
                    self.repository_id,
                    self.workspace_id
                )
            })?;
        workspace
            .base_target
            .as_ref()
            .map(|target| resolve_target_in_authority(&lease, target))
            .transpose()
    }

    pub(crate) fn resolve_git_oid(&self, oid: &GitObjectId) -> Result<SemanticChangeId> {
        let lease = self.manager.read_authority();
        lease
            .metadata()
            .aliases
            .iter()
            .find(|alias| &alias.oid == oid)
            .map(|alias| alias.change_id)
            .ok_or_else(|| {
                anyhow!(
                    "Git commit '{oid}' was never imported into this repository, so kin holds no \
                     semantic change for it; import it with `kin init` in the source checkout, or \
                     name a ref kin already holds"
                )
            })
    }

    pub(crate) fn load_source_blob(&self, digest: kin_model::Hash256) -> Result<Vec<u8>> {
        self.manager
            .load_source_blob(digest)
            .with_context(|| format!("load immutable repository source blob {digest}"))?
            .ok_or_else(|| anyhow!("immutable repository source blob {digest} is absent"))
    }

    pub(crate) fn save_source_blob(&self, digest: kin_model::Hash256, data: &[u8]) -> Result<()> {
        self.manager
            .save_source_blob(digest, data)
            .with_context(|| format!("save immutable repository source blob {digest}"))
    }
}

fn resolve_target_in_authority(
    authority: &RepositoryAuthorityState,
    target: &RefTarget,
) -> Result<SemanticChangeId> {
    let resolved = match target {
        RefTarget::Symbolic { target: name } => authority
            .resolve_ref_target(name)
            .with_context(|| format!("resolve symbolic repository ref '{name}'"))?
            .ok_or_else(|| anyhow!("symbolic repository ref '{name}' is absent"))?,
        target => target.clone(),
    };
    authority
        .resolve_target_change_id(&resolved)
        .context("resolve repository target to an exact semantic change")
}

pub(crate) fn parse_ref_name(value: &str) -> Result<RefName> {
    if value.starts_with("refs/") {
        RefName::from_utf8(value)
            .map_err(|error| anyhow!("invalid fully-qualified repository ref: {error}"))
    } else {
        RefName::branch(value.as_bytes()).map_err(|error| anyhow!("invalid branch name: {error}"))
    }
}

pub(crate) fn parse_git_object_id(value: &str) -> Result<GitObjectId> {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("invalid Git object ID '{value}': expected hexadecimal bytes");
    }
    let bytes = hex::decode(value).with_context(|| format!("invalid Git object ID '{value}'"))?;
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
        length => anyhow::bail!(
            "invalid Git object ID '{value}': expected 20 or 32 bytes, found {length}"
        ),
    }
}
