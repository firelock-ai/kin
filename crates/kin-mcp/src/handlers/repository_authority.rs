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
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

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
pub(crate) fn discover_for_process() -> Result<Option<RequestRepositoryAuthority>> {
    let start = std::env::var_os("KIN_SOURCE_ROOT")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)?;
    let Some(layout) = kin_core::KinLayout::discover(&start) else {
        return Ok(None);
    };
    LocalRepositoryAuthorityBinding::from_layout(&layout)
        .map(RequestRepositoryAuthority::pinned)
        .map(Some)
        .map_err(|error| McpError::Context(format!("graph authority gap: {error}")))
}

pub struct ActiveRepositoryAuthority {
    manager: RepositoryAuthorityManager<LocalFileBackend>,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
}

/// The repository authority one request reads at, and when it was opened.
///
/// Opening authority re-verifies every persisted body against its content
/// address, so it costs whatever the whole store is worth rather than whatever
/// the request asked for. A one-shot process has no one to share that with and
/// opens for itself, which is what every handler did before this type existed.
/// A long-lived server does: it resolves one open per durable publication and
/// hands the same authority to every request that reads at that publication.
///
/// Both arms answer from an open that passed KinDB's complete open-time
/// validation. There is no third arm, no flag, and no path through this type
/// that produces authority which skipped validation -- reuse can only hand back
/// the result of a full validation that already ran over these exact durable
/// bytes. What a server has to get right is not WHETHER the authority it shares
/// was validated but WHICH publication it was validated at; see
/// [`Self::shared`].
#[derive(Clone)]
pub struct RequestRepositoryAuthority {
    binding: LocalRepositoryAuthorityBinding,
    shared: Option<SharedAuthorityResolver>,
}

/// A server's promise to produce authority for the publication a request reads
/// at, run only if the request turns out to need source at all.
///
/// Deferred rather than resolved up front because most of what an MCP dispatch
/// carries never reads a body: resolving eagerly would charge a session or
/// transaction call for the first full open of a publication it does not touch.
pub type SharedAuthorityResolver =
    Arc<dyn Fn() -> Result<Arc<ActiveRepositoryAuthority>> + Send + Sync>;

impl RequestRepositoryAuthority {
    /// Authority this request opens for itself, once, on first use.
    pub fn pinned(binding: LocalRepositoryAuthorityBinding) -> Self {
        Self {
            binding,
            shared: None,
        }
    }

    /// Authority a server resolves for the publication this request reads at.
    ///
    /// The server owns the freshness argument, and it is the whole of what this
    /// type cannot check for itself. Each call to `resolve` must return an
    /// authority opened at a durable publication the server confirmed is still
    /// the one local storage holds, with that confirmation read BEFORE the open
    /// it labels rather than after. A label taken afterwards can name a
    /// publication that landed during the load, which marks older bytes as
    /// current and serves them past the commit that replaced them.
    pub fn shared(
        binding: LocalRepositoryAuthorityBinding,
        resolve: SharedAuthorityResolver,
    ) -> Self {
        Self {
            binding,
            shared: Some(resolve),
        }
    }

    /// Authority a server already resolved for the publication this request
    /// reads at.
    ///
    /// The eager form of [`Self::shared`], for a caller that decided the
    /// request reads source before starting it. The same freshness obligation
    /// applies, at the instant the caller resolved.
    pub fn already_open(
        binding: LocalRepositoryAuthorityBinding,
        authority: Arc<ActiveRepositoryAuthority>,
    ) -> Self {
        Self::shared(binding, Arc::new(move || Ok(Arc::clone(&authority))))
    }

    /// The startup-pinned identity and storage capability behind this
    /// authority, for the surfaces that still take a binding.
    pub fn binding(&self) -> &LocalRepositoryAuthorityBinding {
        &self.binding
    }

    /// The open authority to read this request from.
    ///
    /// Reuses the caller's open when there is one, and otherwise performs the
    /// full validating open. Handlers call this rather than
    /// [`ActiveRepositoryAuthority::open`] so a server's shared open is not
    /// silently bypassed by one read path.
    pub(crate) fn open(&self) -> Result<Arc<ActiveRepositoryAuthority>> {
        match &self.shared {
            Some(resolve) => resolve(),
            None => self.open_fresh(),
        }
    }

    /// Open authority from durable storage, ignoring any open handed in.
    ///
    /// For the paths whose answer is "has this moved?". A shared open describes
    /// the publication its owner sampled, so re-reading it can only ever return
    /// what the caller already saw -- correct for a read, useless for a
    /// re-check. Loading again is the only way to observe a commit that landed
    /// under a separate process since.
    pub(crate) fn open_fresh(&self) -> Result<Arc<ActiveRepositoryAuthority>> {
        ActiveRepositoryAuthority::open(&self.binding).map(Arc::new)
    }
}

impl fmt::Debug for RequestRepositoryAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestRepositoryAuthority")
            .field("binding", &self.binding)
            .field("shared", &self.shared.is_some())
            .finish()
    }
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

/// How many times this process has opened repository authority.
///
/// An open is a full authority recovery -- decode the persisted snapshot, then
/// re-verify every persisted body against its content address -- so its cost is
/// a property of the store, not of the request. That makes the open COUNT, not
/// the wall clock, the honest thing for a test to bound: a query path that opens
/// once per request stays O(1) here no matter how large the store gets, and one
/// that opens per candidate does not. Public because the surfaces that must hold
/// that bound (`semantic_locate`, `kin locate --snippets`) live in other crates.
///
/// It counts LOADS, not requests: serving a request from an authority a server
/// already opened for the same durable publication performs no recovery and is
/// not counted. That is what makes this counter the acceptance instrument for
/// sharing one open across a publication -- it climbs with publications rather
/// than with request volume, and a path that quietly reverted to opening per
/// request would climb with volume again.
pub static REPOSITORY_AUTHORITY_OPEN_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

thread_local! {
    static REPOSITORY_AUTHORITY_OPENS_ON_THREAD: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

/// Repository-authority opens performed so far ON THE CALLING THREAD.
///
/// [`REPOSITORY_AUTHORITY_OPEN_COUNT`] is the honest process total, but a delta
/// taken across a section of one test is not that test's own number: test
/// binaries run in parallel, and any sibling test that projects a body lands in
/// the same counter. A bound asserted on the process total is therefore sound
/// only while no concurrent test opens authority, which is a property of the
/// whole binary that nothing enforces and every new test can silently break.
///
/// This count is immune to that, because another thread's opens are not in it.
/// The one thing a caller must ensure is that the request it is measuring runs
/// on the thread doing the measuring -- an off-thread open is invisible here, so
/// a measured section that hands its work to a worker reads zero. That failure
/// mode is loud rather than silent for the assertion these tests make (`== 1`
/// fails on a zero), which is why it is the right way round.
pub fn repository_authority_opens_on_this_thread() -> u64 {
    REPOSITORY_AUTHORITY_OPENS_ON_THREAD.with(std::cell::Cell::get)
}

impl ActiveRepositoryAuthority {
    /// Perform one full validating open.
    ///
    /// Public so a server can pay for one open per durable publication and hand
    /// the result to [`RequestRepositoryAuthority::already_open`]. Read paths
    /// inside a request go through [`RequestRepositoryAuthority::open`]
    /// instead, so a shared open is never bypassed by one of them.
    pub fn open(binding: &LocalRepositoryAuthorityBinding) -> Result<Self> {
        REPOSITORY_AUTHORITY_OPEN_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        REPOSITORY_AUTHORITY_OPENS_ON_THREAD.with(|opens| opens.set(opens.get() + 1));
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
