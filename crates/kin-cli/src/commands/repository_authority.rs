// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Coherent read access to the active repository-v6 authority.
//!
//! CLI and daemon command helpers use this boundary instead of reconstructing
//! refs, workspace state, aliases, or source bytes from legacy sidecars, Git,
//! or the working directory.

use anyhow::{anyhow, Context, Result};
use kin_db::{
    AuthorityPayloadStats, LocalFileBackend, MaterializedGraphSectionOutcome,
    RepositoryAuthorityManager, RepositoryAuthorityState,
};
use kin_model::{
    GitObjectId, RefName, RefTarget, RepositoryId, RootBundle, SemanticChangeId, WorkspaceId,
    WorkspaceState,
};
use serde::{Deserialize, Serialize};

pub struct ActiveRepositoryAuthority {
    manager: RepositoryAuthorityManager<LocalFileBackend>,
    payload_stats: Option<AuthorityPayloadStats>,
    pub(crate) repository_id: RepositoryId,
    pub(crate) workspace_id: WorkspaceId,
}

/// Machine-readable result of explicitly memoizing one workspace base graph.
///
/// This is deliberately a representation result rather than a repository
/// commit receipt. Materialization may advance the storage backend's fenced
/// publication cursor, but it preserves the logical authority generation and
/// roots exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphSectionMaterialization {
    pub schema: String,
    pub scope: GraphSectionMaterializationScope,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub state: GraphSectionMaterializationState,
    pub authority_generation: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_semantic_change_id_hex"
    )]
    pub resolved_at: Option<SemanticChangeId>,
}

mod optional_semantic_change_id_hex {
    use kin_model::{Hash256, SemanticChangeId};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<SemanticChangeId>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SemanticChangeId>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|value| {
                Hash256::from_hex(&value)
                    .map(SemanticChangeId::from_hash)
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphSectionMaterializationScope {
    WorkspaceBase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphSectionMaterializationState {
    Persisted,
    AlreadyCurrent,
    NoBaseTarget,
}

impl GraphSectionMaterialization {
    const SCHEMA: &'static str = "kin.graph-section-materialization.v1";

    fn from_kin_db(
        repository_id: RepositoryId,
        workspace_id: WorkspaceId,
        outcome: MaterializedGraphSectionOutcome,
    ) -> Self {
        let (state, authority_generation, resolved_at) = match outcome {
            MaterializedGraphSectionOutcome::Persisted {
                resolved_at,
                authority_generation,
            } => (
                GraphSectionMaterializationState::Persisted,
                authority_generation,
                Some(resolved_at),
            ),
            MaterializedGraphSectionOutcome::AlreadyCurrent {
                resolved_at,
                authority_generation,
            } => (
                GraphSectionMaterializationState::AlreadyCurrent,
                authority_generation,
                Some(resolved_at),
            ),
            MaterializedGraphSectionOutcome::NoBaseTarget {
                authority_generation,
            } => (
                GraphSectionMaterializationState::NoBaseTarget,
                authority_generation,
                None,
            ),
        };
        Self {
            schema: Self::SCHEMA.to_string(),
            scope: GraphSectionMaterializationScope::WorkspaceBase,
            repository_id,
            workspace_id,
            state,
            authority_generation,
            resolved_at,
        }
    }

    pub fn human_line(&self) -> String {
        match (&self.state, &self.resolved_at) {
            (GraphSectionMaterializationState::Persisted, Some(resolved_at)) => format!(
                "Persisted the workspace base graph section at {resolved_at} (authority generation {}).",
                self.authority_generation
            ),
            (GraphSectionMaterializationState::AlreadyCurrent, Some(resolved_at)) => format!(
                "The workspace base graph section is already current at {resolved_at} (authority generation {}).",
                self.authority_generation
            ),
            (GraphSectionMaterializationState::NoBaseTarget, None) => format!(
                "No workspace base graph section exists yet because this workspace is unborn (authority generation {}).",
                self.authority_generation
            ),
            // Construction is private and keeps the state and target paired.
            // This arm still prevents malformed wire input from being rendered
            // as if it were a trustworthy product outcome.
            _ => "The graph-section materialization response was internally inconsistent."
                .to_string(),
        }
    }
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
    /// `#[track_caller]` so the log at the open names the READ that wanted an
    /// authority rather than this wrapper. Without it every pinned open in the
    /// product attributes to one line here, which is attribution being useless
    /// in the most convincing way.
    #[track_caller]
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
    #[track_caller]
    pub fn open(binding: &kin_core::LocalRepositoryAuthorityBinding) -> Result<Self> {
        let opens = REPOSITORY_AUTHORITY_OPENS_ON_THREAD.with(|opens| {
            opens.set(opens.get() + 1);
            opens.get()
        });
        // Who asked, in the product's own log, at the moment of asking.
        //
        // kin-db already logs `repository authority open` with its timings, and
        // one `kin graph status` on a converted repository produced twelve of
        // them with nine concurrent, each decoding the whole snapshot and
        // re-verifying every persisted body. That count says the cost is a
        // multiplier rather than a working set. It says nothing about WHICH
        // callers make it, and that is the difference between fixing one site
        // and fixing the mechanism.
        //
        // `#[track_caller]` names the call site rather than a backtrace and
        // costs nothing at runtime, so attributing those twelve is a grep over
        // one run instead of an argument from source. The counter beside it is
        // the same thread-local the tests assert on, so a burst on one thread
        // is visible without correlating timestamps.
        //
        // Deliberately `info` and not `debug`: the count is what an operator
        // needs when a read is slow, and a level nobody turns on is a line
        // nobody reads.
        let caller = std::panic::Location::caller();
        tracing::info!(
            repository = %binding.repository_id(),
            caller = %format_args!("{}:{}", caller.file(), caller.line()),
            opens_on_this_thread = opens,
            "opening repository authority, which re-verifies every persisted body"
        );
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

    /// Persist the current workspace base graph as an idempotent acceleration
    /// section without changing semantic authority.
    pub(crate) fn materialize_workspace_base_graph_section(
        &self,
    ) -> Result<GraphSectionMaterialization> {
        let outcome = self
            .manager
            .materialize_workspace_base_graph_section(&self.repository_id, &self.workspace_id)
            .with_context(|| {
                format!(
                    "materialize workspace {} base graph section for repository {}",
                    self.workspace_id, self.repository_id
                )
            })?
            .ok_or_else(|| {
                anyhow!(
                    "repository {} has no workspace {} in its authority",
                    self.repository_id,
                    self.workspace_id
                )
            })?;
        Ok(GraphSectionMaterialization::from_kin_db(
            self.repository_id.clone(),
            self.workspace_id,
            outcome,
        ))
    }

    /// Whether an open of this store serves its workspace base from the
    /// persisted graph section or folds it out of history, and how big that
    /// fold is.
    ///
    /// Reads the envelope this open already holds and decodes nothing; see
    /// [`kin_core::graph_section`] for why the exact fold count is taken only
    /// where it is free.
    pub(crate) fn graph_section_state(&self) -> kin_core::graph_section::GraphSectionState {
        let lease = self.manager.read_authority();
        kin_core::graph_section::read(&lease, &self.workspace_id)
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
                    "repository {} has no workspace {} in its authority",
                    self.repository_id,
                    self.workspace_id
                )
            })?;
        Ok((workspace, lease.roots().clone()))
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
                    "repository {} has no workspace {} in its authority",
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

/// Materialize the current workspace base without starting or sharing a
/// daemon runtime.
///
/// The runtime capability is acquired before the first whole-authority open
/// and remains held until that manager is dropped. A running daemon therefore
/// makes the command fail before it can fold history or write representation
/// bytes, and a daemon cannot begin opening the repository during the rewrite.
pub(crate) fn materialize_workspace_base_offline(
    layout: &kin_core::KinLayout,
) -> Result<GraphSectionMaterialization> {
    materialize_workspace_base_offline_within(
        layout,
        kin_daemon_spawn::REPOSITORY_RUNTIME_AUTHORITY_RETRY_BUDGET,
    )
}

fn materialize_workspace_base_offline_within(
    layout: &kin_core::KinLayout,
    budget: std::time::Duration,
) -> Result<GraphSectionMaterialization> {
    let runtime = crate::daemon_client::acquire_repository_runtime_authority_within(
        layout.root(),
        budget,
    )
    .with_context(|| {
        format!(
            "acquire repository runtime authority for {}",
            layout.root().display()
        )
    })?
    .ok_or_else(|| {
        anyhow!(
            "another Kin process holds repository runtime authority for {}; run `kin daemon stop`, then retry `kin graph materialize`",
            layout.root().display()
        )
    })?;

    let outcome = {
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)
            .context("bind repository authority for offline graph-section materialization")?;
        let authority = ActiveRepositoryAuthority::open(&binding)
            .context("open repository authority for offline graph-section materialization")?;
        authority.materialize_workspace_base_graph_section()
    };
    drop(runtime);
    outcome
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_section_materialization_keeps_all_three_backend_outcomes_distinct() {
        let resolved_at = SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([0x29; 32]));
        let repository_id = RepositoryId::new("graph-section-test").unwrap();
        let workspace_id = WorkspaceId::from_uuid(uuid::Uuid::from_u128(0x29));
        let cases = [
            (
                MaterializedGraphSectionOutcome::Persisted {
                    resolved_at,
                    authority_generation: 7,
                },
                GraphSectionMaterializationState::Persisted,
                Some(resolved_at),
            ),
            (
                MaterializedGraphSectionOutcome::AlreadyCurrent {
                    resolved_at,
                    authority_generation: 7,
                },
                GraphSectionMaterializationState::AlreadyCurrent,
                Some(resolved_at),
            ),
            (
                MaterializedGraphSectionOutcome::NoBaseTarget {
                    authority_generation: 7,
                },
                GraphSectionMaterializationState::NoBaseTarget,
                None,
            ),
        ];

        for (backend, state, target) in cases {
            let mapped = GraphSectionMaterialization::from_kin_db(
                repository_id.clone(),
                workspace_id,
                backend,
            );
            assert_eq!(mapped.schema, "kin.graph-section-materialization.v1");
            assert_eq!(
                mapped.scope,
                GraphSectionMaterializationScope::WorkspaceBase
            );
            assert_eq!(mapped.state, state);
            assert_eq!(mapped.authority_generation, 7);
            assert_eq!(mapped.resolved_at, target);
            assert_eq!(mapped.repository_id, repository_id);
            assert_eq!(mapped.workspace_id, workspace_id);
        }
    }

    #[test]
    fn graph_section_materialization_json_names_state_and_omits_unborn_target() {
        let outcome = GraphSectionMaterialization::from_kin_db(
            RepositoryId::new("graph-section-test").unwrap(),
            WorkspaceId::from_uuid(uuid::Uuid::from_u128(0x30)),
            MaterializedGraphSectionOutcome::NoBaseTarget {
                authority_generation: 3,
            },
        );
        let json = serde_json::to_value(outcome).unwrap();
        assert_eq!(json["scope"], "workspace_base");
        assert_eq!(json["state"], "no_base_target");
        assert_eq!(json["authority_generation"], 3);
        assert!(json.get("resolved_at").is_none());
    }

    #[test]
    fn graph_section_materialization_json_names_the_base_target_as_hex() {
        let resolved_at = SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([0x29; 32]));
        let outcome = GraphSectionMaterialization::from_kin_db(
            RepositoryId::new("graph-section-test").unwrap(),
            WorkspaceId::from_uuid(uuid::Uuid::from_u128(0x31)),
            MaterializedGraphSectionOutcome::AlreadyCurrent {
                resolved_at,
                authority_generation: 4,
            },
        );

        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["resolved_at"], "29".repeat(32));

        let round_trip: GraphSectionMaterialization = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip, outcome);
    }

    #[test]
    fn offline_materialization_refuses_runtime_contention_before_authority_open() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(directory.path()).unwrap();
        let held = crate::daemon_client::acquire_repository_runtime_authority_within(
            initialized.layout.root(),
            std::time::Duration::ZERO,
        )
        .unwrap()
        .expect("test owns repository runtime authority");
        let opens_before = repository_authority_opens_on_this_thread();

        let error = materialize_workspace_base_offline_within(
            &initialized.layout,
            std::time::Duration::ZERO,
        )
        .unwrap_err();

        assert!(error.to_string().contains("kin daemon stop"), "{error:#}");
        assert_eq!(
            repository_authority_opens_on_this_thread(),
            opens_before,
            "contention must be decided before a whole repository authority open"
        );

        drop(held);
        let outcome = materialize_workspace_base_offline_within(
            &initialized.layout,
            std::time::Duration::ZERO,
        )
        .unwrap();
        assert_eq!(
            outcome.state,
            GraphSectionMaterializationState::NoBaseTarget
        );
        assert_eq!(
            repository_authority_opens_on_this_thread(),
            opens_before + 1,
            "the successful maintenance arm opens authority exactly once"
        );
    }
}
