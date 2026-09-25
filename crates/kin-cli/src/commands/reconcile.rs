// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Explicit repository-v6 session observation boundary.
//!
//! This module is the only runtime path permitted to observe editable session
//! bytes. It never answers a semantic query from the filesystem. A complete,
//! bounded, no-follow observation is converted into one desired
//! [`kin_model::ResolvedTree`]; the daemon then admits that tree through a
//! repository-v6 compare-and-swap and the exact primary-projection WAL.

#[cfg(unix)]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
#[cfg(any(unix, test))]
use kin_model::TreeEntry;
use kin_model::{ArtifactId, Hash256, RepoPath, ResolvedTree, TreeDelta};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use super::repository_authority::ActiveRepositoryAuthority;
use crate::commands::session_workspace::SessionWorkspaceBase;
pub use crate::commands::write_back::{
    SessionWriteBack, Toolchain, WithheldChange, WithheldReason,
};

pub const RECONCILE_SUMMARY_SCHEMA: &str = "kin.session-reconcile.v1";

// Bounds for the retained no-follow session observation, which only the Unix
// traversal below performs.
#[cfg(unix)]
const MAX_SESSION_BASE_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(unix)]
const MAX_SESSION_ENTRIES: usize = 100_000;
#[cfg(unix)]
const MAX_SESSION_DIRECTORIES: usize = 100_000;
#[cfg(unix)]
const MAX_SESSION_DEPTH: usize = 256;
#[cfg(unix)]
const MAX_SESSION_PATH_BYTES: usize = 4096;
#[cfg(unix)]
const MAX_SESSION_BODY_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(unix)]
const MAX_SESSION_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    pub session_dir: PathBuf,
    #[serde(default)]
    pub confirm_mass_deletion: bool,
    /// Which of the session's observed changes may be admitted. Absent reads
    /// as a person's session: everything but new build outputs.
    #[serde(default)]
    pub write_back: SessionWriteBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", content = "value", rename_all = "snake_case")]
pub enum ReconcilePath {
    Utf8(String),
    Hex(String),
}

impl From<&RepoPath> for ReconcilePath {
    fn from(path: &RepoPath) -> Self {
        path.as_utf8().map_or_else(
            || Self::Hex(hex::encode(path.as_bytes())),
            |path| Self::Utf8(path.to_string()),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileChangeKind {
    Added,
    Modified,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileChange {
    pub kind: ReconcileChangeKind,
    pub artifact_id: ArtifactId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<ReconcilePath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_path: Option<ReconcilePath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileSummary {
    pub schema: String,
    /// The session's own reconcile operation. An unchanged session commits
    /// nothing under it.
    pub operation_id: kin_model::OperationId,
    pub repository_id: kin_model::RepositoryId,
    /// Repository authority generation once this reconcile finished. A
    /// publication reports its receipt's generation. An unchanged session
    /// publishes nothing, so it reports the generation current when it closed,
    /// which other writers may have advanced past the session's base.
    pub authority_generation: u64,
    /// Workspace generation once this reconcile finished, by the same rule.
    pub workspace_generation: u64,
    /// Tree the session was materialized from.
    pub previous_tree_hash: Hash256,
    /// Tree the session's observation asks authority to hold. For an unchanged
    /// session it equals `previous_tree_hash`, and nothing is published.
    pub desired_tree_hash: Hash256,
    pub idempotent_replay: bool,
    pub changed: bool,
    pub added: usize,
    pub modified: usize,
    pub removed: usize,
    pub observed_materialized_artifacts: usize,
    pub preserved_graph_only_artifacts: usize,
    pub observed_body_bytes: u64,
    pub semantic_files_enriched: usize,
    pub semantic_enrichment_failures: usize,
    pub changes: Vec<ReconcileChange>,
    /// Observed changes the session's write-back policy did not admit, each
    /// with the reason. A withheld change is not in `changes` and is not
    /// counted by `added`, `modified` or `removed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld: Vec<WithheldChange>,
}

/// Repository and workspace generations read from current authority when a
/// session base was last authenticated.
///
/// An unchanged session may close against a base other writers have since
/// advanced, so its summary reports these rather than the snapshot generations
/// the base recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentAuthorityGenerations {
    pub authority: u64,
    pub workspace: u64,
}

/// Retained observation identities, with a separate durable location. Its
/// private fields prevent construction without an exact session observation.
pub struct RetainedSessionPublicationBinding {
    binding: kin_db::storage::SessionPublicationBinding,
    locator: kin_db::storage::SessionPublicationLocator,
}

impl RetainedSessionPublicationBinding {
    pub fn binding(&self) -> &kin_db::storage::SessionPublicationBinding {
        &self.binding
    }

    pub fn locator(&self) -> &kin_db::storage::SessionPublicationLocator {
        &self.locator
    }
}

/// Complete, twice-verified input to the daemon's authority transaction.
///
/// Source bodies have already been written and read back from the daemon's
/// non-authoritative ingestion CAS, then released from request memory.
/// Repository publication reloads them from CAS by identity.
///
/// The observation owns the retained no-follow directory capability it was
/// taken through, so the capability outlives planning and reaches publication
/// rather than being released when the scanner returns. Every field is
/// private and every constructor path runs the scanner, so no caller outside
/// this module can fabricate an observation or hand publication a desired tree
/// that no retained walk produced.
///
/// The seal is a type-level one. Removing the capability, or building this
/// value by hand, does not compile:
///
/// ```compile_fail
/// # use kin_cli::commands::reconcile::SessionReconcileObservation;
/// # fn fabricate(base: kin_cli::commands::session_workspace::SessionWorkspaceBase,
/// #              tree: kin_model::ResolvedTree) -> SessionReconcileObservation {
/// SessionReconcileObservation {
///     base,
///     desired_tree: tree,
///     deltas: Vec::new(),
///     observed_materialized_artifacts: 0,
///     observed_body_bytes: 0,
///     preserved_graph_only_artifacts: 0,
/// }
/// # }
/// ```
pub struct SessionReconcileObservation {
    #[cfg(unix)]
    retained: RetainedSession,
    #[cfg(unix)]
    base_bytes: Vec<u8>,
    base: SessionWorkspaceBase,
    desired_tree: ResolvedTree,
    deltas: Vec<TreeDelta>,
    observed_materialized_artifacts: usize,
    observed_body_bytes: u64,
    preserved_graph_only_artifacts: usize,
    current_generations: Option<CurrentAuthorityGenerations>,
    #[cfg(unix)]
    filter: ObservationFilter,
    withheld: Vec<WithheldChange>,
}

/// Which observed changes an observation admits.
///
/// A request names a [`SessionWriteBack`]. `Unfiltered` is what every session
/// admitted before build outputs were withheld, and only the recovery of a
/// publication prepared under it reads it: that publication's target is
/// already acknowledged, and recovery must reproduce it exactly.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationFilter {
    Unfiltered,
    Policy(SessionWriteBack),
}

#[cfg(unix)]
impl ObservationFilter {
    /// Whether this filter withholds anything, and so whether the scan may
    /// skip a generated directory graph truth holds nothing under.
    fn filters(self) -> bool {
        matches!(self, Self::Policy(_))
    }

    /// This filter when its policy satisfies `keep`, and `Unfiltered`
    /// otherwise.
    fn filter(self, keep: impl Fn(SessionWriteBack) -> bool) -> Self {
        match self {
            Self::Policy(policy) if keep(policy) => self,
            _ => Self::Unfiltered,
        }
    }

    /// Every filter a recovered publication may have been planned under.
    fn recovery_candidates() -> Vec<Self> {
        let mut candidates = vec![
            Self::Policy(SessionWriteBack::ExceptBuildOutputs),
            Self::Policy(SessionWriteBack::ToolchainManifests),
        ];
        candidates.extend(
            crate::commands::write_back::Toolchain::ALL
                .into_iter()
                .map(|toolchain| Self::Policy(SessionWriteBack::ManifestsOf(toolchain))),
        );
        candidates.push(Self::Unfiltered);
        candidates
    }
}

impl SessionReconcileObservation {
    /// Opaque identity of this observed session, including its exact base
    /// bytes and retained no-follow directory chain. This is not a path ID.
    pub fn publication_binding(&self) -> Result<RetainedSessionPublicationBinding> {
        #[cfg(unix)]
        {
            self.retained
                .publication_binding(&self.base, &self.base_bytes)
        }
        #[cfg(not(unix))]
        {
            bail!("retained session publication binding is unavailable on this platform")
        }
    }

    pub fn base(&self) -> &SessionWorkspaceBase {
        &self.base
    }

    pub fn desired_tree(&self) -> &ResolvedTree {
        &self.desired_tree
    }

    pub fn deltas(&self) -> &[TreeDelta] {
        &self.deltas
    }

    pub const fn observed_materialized_artifacts(&self) -> usize {
        self.observed_materialized_artifacts
    }

    pub const fn observed_body_bytes(&self) -> u64 {
        self.observed_body_bytes
    }

    pub const fn preserved_graph_only_artifacts(&self) -> usize {
        self.preserved_graph_only_artifacts
    }

    /// Generations current when this observation's base was last
    /// authenticated. `None` for an acknowledged preparation, whose receipt
    /// reports its own generation.
    pub const fn current_generations(&self) -> Option<CurrentAuthorityGenerations> {
        self.current_generations
    }

    pub fn changes(&self) -> Vec<ReconcileChange> {
        self.deltas.iter().map(reconcile_change).collect()
    }

    /// Observed changes the session's write-back policy did not admit.
    pub fn withheld(&self) -> &[WithheldChange] {
        &self.withheld
    }

    /// Re-scan under the retained no-follow capability before acknowledgement.
    /// The already authorized target must remain byte-exact; this does not
    /// authorize new changes or make an atomic claim about future writers.
    pub fn revalidate_publication_inputs(
        &self,
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            let (scan, _) = scan_retained_projection(
                &self.retained,
                layout,
                &self.base,
                &self.base_bytes,
                blobs,
                self.filter,
            )?;
            if build_desired_tree(&self.base, &scan, self.filter)?.0 != self.desired_tree {
                bail!("session target changed before publication acknowledgement");
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (layout, blobs);
            bail!("retained session publication revalidation is unavailable on this platform")
        }
    }

    /// Re-prove the retained capability still names the observed session.
    ///
    /// Publication calls this after planning, so the window between the last
    /// scan and the authority transaction is covered by the same directory
    /// identities and the same base bytes the plan was derived from.
    pub fn revalidate_retained_capability(&self, layout: &kin_core::KinLayout) -> Result<()> {
        #[cfg(unix)]
        {
            self.retained
                .revalidate_visible(layout, &self.base_bytes)
                .context("revalidate retained session capability before publication")
        }
        #[cfg(not(unix))]
        {
            let _ = layout;
            bail!("retained session capability is unavailable on this platform")
        }
    }
}

pub async fn run(session_id: Option<String>, confirm_mass_deletion: bool) -> Result<()> {
    let cwd = std::env::current_dir().context("resolve current directory")?;
    let layout = crate::commands::require_repository_layout_at(&cwd)?;
    run_for_layout(&layout, session_id.as_deref(), confirm_mass_deletion).await
}

/// Admit one session projection and collect it.
///
/// Admission is what retires a projection, so this is the collector for every
/// retained session: the surfaces that never close their own projection
/// (`kin open`, `kin exec --keep`, any run kept by a non-zero exit) all end
/// here. The removal is strictly after the daemon reports success, so a
/// refused or failed reconcile leaves the projection on disk for the operator
/// to inspect and retry.
pub async fn run_for_layout(
    layout: &kin_core::KinLayout,
    session_id: Option<&str>,
    confirm_mass_deletion: bool,
) -> Result<()> {
    let session_dir = resolve_session_directory(layout, session_id)?;
    let base_url = crate::daemon_client::resolve_daemon_url(layout)
        .await?
        .ok_or_else(|| {
            crate::daemon_client::daemon_required_error("exact session reconciliation", layout)
        })?;
    let client = crate::daemon_client::DaemonClient::from_base_url_for_layout(base_url, layout)?;
    let summary = client
        .reconcile(&ReconcileRequest {
            session_dir: session_dir.clone(),
            confirm_mass_deletion,
            write_back: SessionWriteBack::default(),
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    crate::commands::session_run::discard(&session_dir).with_context(|| {
        format!(
            "remove the admitted session workspace {}; its changes are already in repository \
             authority, so the reconcile must not be retried",
            session_dir.display()
        )
    })?;
    Ok(())
}

/// Observe a person's session: everything it changed except new build
/// outputs. See [`observe_session_workspace_under`].
pub fn observe_session_workspace(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    session_dir: &Path,
    blobs: &kin_blobs::BlobStore,
    confirm_mass_deletion: bool,
) -> Result<SessionReconcileObservation> {
    observe_session_workspace_under(
        layout,
        binding,
        session_dir,
        blobs,
        confirm_mass_deletion,
        SessionWriteBack::default(),
    )
}

/// Observe one session under the write-back policy its caller names. The
/// changes the policy does not admit are left out of the desired tree and
/// reported by [`SessionReconcileObservation::withheld`].
pub fn observe_session_workspace_under(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    session_dir: &Path,
    blobs: &kin_blobs::BlobStore,
    confirm_mass_deletion: bool,
    write_back: SessionWriteBack,
) -> Result<SessionReconcileObservation> {
    observe_session_workspace_inner(
        layout,
        binding,
        session_dir,
        blobs,
        confirm_mass_deletion,
        None,
        write_back,
    )
}

/// Discover one retained session's acknowledged operation before taking the
/// backend publication freeze. This loads through the caller's existing
/// authority manager; it neither opens another manager nor authorizes replay.
/// An operation ID alone is insufficient: its exact base, control identity and
/// locator must still belong to this retained session.
pub fn lookup_prepared_session_workspace(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    session_dir: &Path,
    authority: &kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>,
) -> Result<Option<kin_db::storage::PreparedSessionPublication>> {
    #[cfg(unix)]
    {
        let retained = RetainedSession::open(layout, session_dir)?;
        let base_bytes = retained.read_base()?;
        let base: SessionWorkspaceBase =
            serde_json::from_slice(&base_bytes).context("decode exact session base")?;
        base.validate().context("validate exact session base")?;
        validate_local_binding_identity(binding, &base)?;
        if authority.read_authority().metadata().repository_id != base.repository_id {
            bail!("session lookup authority belongs to another repository");
        }
        let prepared = authority.load_prepared_session_publication(base.reconcile_operation_id)?;
        if let Some(prepared) = &prepared {
            validate_prepared_base(&retained, &base, &base_bytes, prepared)?;
        }
        retained.revalidate_visible(layout, &base_bytes)?;
        binding.revalidate_pinned_namespace()?;
        Ok(prepared)
    }
    #[cfg(not(unix))]
    {
        let _ = (layout, binding, session_dir, authority);
        bail!("retained session publication lookup is unavailable on this platform")
    }
}

/// Re-observe the immutable target of one acknowledged local preparation.
/// The locator never resolves "latest" and legacy portable IDs are not paths.
/// A preparation acknowledges only its exact desired tree, not permission to
/// admit a newly observed mass deletion or another changed target.
/// This checks the manager-admitted handle and retained namespace without
/// reopening authority, so it can run under a publication freeze and can
/// verify a historical receipt without replacing newer repository roots.
pub fn observe_prepared_session_workspace(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    blobs: &kin_blobs::BlobStore,
    prepared: &kin_db::storage::PreparedSessionPublication,
) -> Result<SessionReconcileObservation> {
    let kin_db::storage::SessionPublicationLocator::RetainedUnixV1 { session_leaf } =
        prepared.recovery_locator()?;
    validate_session_leaf(session_leaf)?;
    observe_session_workspace_inner(
        layout,
        binding,
        &layout.runs_dir().join(session_leaf),
        blobs,
        false,
        Some(prepared),
        SessionWriteBack::default(),
    )
}

fn observe_session_workspace_inner(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    session_dir: &Path,
    blobs: &kin_blobs::BlobStore,
    confirm_mass_deletion: bool,
    prepared: Option<&kin_db::storage::PreparedSessionPublication>,
    write_back: SessionWriteBack,
) -> Result<SessionReconcileObservation> {
    #[cfg(unix)]
    {
        let retained = RetainedSession::open(layout, session_dir)?;
        let base_bytes = retained.read_base()?;
        let base: SessionWorkspaceBase =
            serde_json::from_slice(&base_bytes).context("decode exact session base")?;
        base.validate().context("validate exact session base")?;
        if let Some(prepared) = prepared {
            validate_local_binding_identity(binding, &base)?;
            validate_prepared_base(&retained, &base, &base_bytes, prepared)?;
            binding.revalidate_pinned_namespace()?;
        } else {
            // Authenticate before any projection byte is read. Whether a base
            // that is no longer current may still close is decided once the
            // exact deltas are known.
            session_base_standing(binding, &base)?;
        }

        // A fresh observation admits what its caller's policy admits. Recovery
        // of an acknowledged publication must reproduce that publication's
        // exact target, which was planned under a policy the recovery does not
        // know, so it takes the first policy that does, the legacy unfiltered
        // one included for a publication prepared before build outputs were
        // withheld. The target is already acknowledged, so this admits
        // nothing new: a session that matches none of them still fails.
        let candidates = if prepared.is_some() {
            ObservationFilter::recovery_candidates()
        } else {
            vec![ObservationFilter::Policy(write_back)]
        };
        let acknowledged = match prepared {
            Some(prepared) => {
                let mutation = prepared
                    .transaction()
                    .workspace_mutation
                    .as_ref()
                    .ok_or_else(|| anyhow!("prepared session has no workspace target"))?;
                let expected = base
                    .source_workspace
                    .tree
                    .apply(&mutation.tree_deltas)
                    .context("derive acknowledged exact session target")?;
                Some((expected, mutation.new_tree_hash))
            }
            None => None,
        };
        let mut chosen = None;
        let mut filtered_scan: Option<(SessionScan, usize)> = None;
        let mut unfiltered_scan: Option<(SessionScan, usize)> = None;
        for filter in candidates.iter().copied() {
            let slot = if filter.filters() {
                &mut filtered_scan
            } else {
                &mut unfiltered_scan
            };
            if slot.is_none() {
                *slot = Some(scan_retained_projection(
                    &retained,
                    layout,
                    &base,
                    &base_bytes,
                    blobs,
                    filter,
                )?);
            }
            let (scan, graph_only_count) = slot.as_ref().expect("scanned above");
            let (desired_tree, withheld) = build_desired_tree(&base, scan, filter)?;
            if let Some((expected, expected_hash)) = &acknowledged {
                if expected != &desired_tree
                    || &kin_model::compute_resolved_tree_hash(&desired_tree)? != expected_hash
                {
                    continue;
                }
            }
            chosen = Some((
                filter,
                desired_tree,
                withheld,
                scan.total_bytes,
                scan.entries.len(),
                *graph_only_count,
            ));
            break;
        }
        let Some((
            filter,
            desired_tree,
            withheld,
            observed_body_bytes,
            observed_materialized_artifacts,
            graph_only_count,
        )) = chosen
        else {
            bail!("observed session differs from acknowledged immutable target");
        };
        if prepared.is_some() {
            binding.revalidate_pinned_namespace()?;
        }

        let deltas = kin_core::exact_tree_correction(&base.source_workspace.tree, &desired_tree)
            .context("plan exact session tree transition")?;
        let current_generations = if prepared.is_some() {
            None
        } else {
            // Read after both scans, so authority that moved while the
            // projection was observed is judged as it now stands.
            let (standing, generations) = session_base_standing(binding, &base)?;
            match standing {
                SessionBaseStanding::Current => {}
                SessionBaseStanding::Reconciled if !deltas.is_empty() => {}
                SessionBaseStanding::Superseded if deltas.is_empty() => {}
                SessionBaseStanding::Reconciled => bail!(
                    "unchanged session base is stale or tampered: repository roots/workspace no \
                     longer match its exact authority lease"
                ),
                SessionBaseStanding::Superseded => bail!(
                    "session base is stale: repository authority advanced after this session was \
                     materialized, and a changed session is never admitted onto newer authority"
                ),
            }
            enforce_mass_deletion(
                base.source_workspace.tree.len(),
                &deltas,
                confirm_mass_deletion,
            )?;
            Some(generations)
        };

        Ok(SessionReconcileObservation {
            retained,
            base_bytes,
            base,
            desired_tree,
            deltas,
            observed_materialized_artifacts,
            observed_body_bytes,
            preserved_graph_only_artifacts: graph_only_count,
            current_generations,
            filter,
            withheld,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (
            layout,
            binding,
            session_dir,
            blobs,
            confirm_mass_deletion,
            prepared,
            write_back,
        );
        bail!(
            "exact session reconciliation is fail-closed on this platform until retained \
             no-follow directory traversal is available"
        )
    }
}

#[cfg(unix)]
fn scan_retained_projection(
    retained: &RetainedSession,
    layout: &kin_core::KinLayout,
    base: &SessionWorkspaceBase,
    base_bytes: &[u8],
    blobs: &kin_blobs::BlobStore,
    filter: ObservationFilter,
) -> Result<(SessionScan, usize)> {
    retained.revalidate_visible(layout, base_bytes)?;
    let context = ScanContext::new(&base.source_workspace.tree, filter);
    let mut graph_only_paths = Vec::new();
    for artifact in base.source_workspace.tree.artifacts_by_path() {
        let disposition = kin_core::source_projection_disposition(&artifact.path, artifact.entry)
            .with_context(|| {
            format!(
                "classify exact session source projection member {}",
                artifact.path
            )
        })?;
        if disposition != kin_core::SourceProjectionDisposition::Materialized {
            graph_only_paths.push(artifact.path.clone());
        }
    }
    let first = retained.scan(&graph_only_paths, &context, Some(blobs))?;
    let second = retained.scan(&graph_only_paths, &context, None)?;
    if first != second {
        bail!("session projection changed between exact observations");
    }
    retained.revalidate_visible(layout, base_bytes)?;
    Ok((first, graph_only_paths.len()))
}

#[cfg(unix)]
fn validate_local_binding_identity(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    base: &SessionWorkspaceBase,
) -> Result<()> {
    if binding.repository_id() != &base.repository_id {
        bail!("session base repository identity does not match this repository");
    }
    if binding.workspace_id() != base.source_workspace.workspace_id {
        bail!("session base workspace identity does not match this workspace");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_prepared_base(
    retained: &RetainedSession,
    base: &SessionWorkspaceBase,
    base_bytes: &[u8],
    prepared: &kin_db::storage::PreparedSessionPublication,
) -> Result<()> {
    let observed = retained.publication_binding(base, base_bytes)?;
    let transaction = prepared.transaction();
    let mutation = transaction
        .workspace_mutation
        .as_ref()
        .ok_or_else(|| anyhow!("prepared session has no workspace target"))?;
    if observed.binding() != prepared.binding()
        || observed.locator() != prepared.recovery_locator()?
        || transaction.operation_id != base.reconcile_operation_id
        || transaction.repository_id != base.repository_id
        || transaction.expected_roots != base.authority_roots
        || mutation.workspace_id != base.source_workspace.workspace_id
        || mutation.expected != workspace_expectation(&base.source_workspace)
    {
        bail!("prepared session operation, base, locator, or retained control identity differs");
    }
    Ok(())
}

/// The complete compare-and-swap expectation a workspace mutation records for
/// the exact workspace state it replaces.
#[cfg(unix)]
fn workspace_expectation(workspace: &kin_model::WorkspaceState) -> kin_model::WorkspaceExpectation {
    kin_model::WorkspaceExpectation::MustEqual {
        generation: workspace.generation,
        head: workspace.head.clone(),
        base_target: workspace.base_target.clone(),
        base_tree_hash: workspace.base_tree_hash,
        tree_hash: workspace.tree_hash,
        semantic_overlay_hash: workspace.semantic_overlay_hash,
        admission_policy: workspace.admission_policy,
    }
}

fn resolve_session_directory(
    layout: &kin_core::KinLayout,
    requested: Option<&str>,
) -> Result<PathBuf> {
    let runs = layout.runs_dir();
    if let Some(requested) = requested {
        let name = if requested.starts_with("session-") {
            requested.to_string()
        } else {
            format!("session-{requested}")
        };
        validate_session_leaf(&name)?;
        return Ok(runs.join(name));
    }

    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(&runs).with_context(|| format!("read {}", runs.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_utf8) = name.to_str() else {
            continue;
        };
        if validate_session_leaf(name_utf8).is_err() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        candidates.push((
            metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            name,
        ));
    }
    candidates.sort();
    let (_, name) = candidates
        .pop()
        .ok_or_else(|| anyhow!("no exact session workspace exists under {}", runs.display()))?;
    Ok(runs.join(name))
}

fn validate_session_leaf(name: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(component)) if component == name)
        || components.next().is_some()
        || !name.starts_with("session-")
        || name.len() == "session-".len()
    {
        bail!("session identity must use one 'session-<id>' path component");
    }
    Ok(())
}

/// How an authenticated session base relates to current repository authority.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionBaseStanding {
    /// The exact lease the session was materialized from is still current.
    Current,
    /// The session's own reconcile operation is what advanced authority.
    Reconciled,
    /// Other operations advanced authority after an authentic base. Only an
    /// exactly unchanged projection may close against it, and only as a no-op.
    Superseded,
}

/// Bind an editable session base to persisted repository authority.
///
/// A base is current when its exact roots and workspace still are, and
/// reconciled when a receipt proves the session's own operation moved
/// authority from them. Any other base must be proven authentic history before
/// it is read as superseded, and is refused otherwise: a forged base that
/// matches the projection bytes would let an unchanged-looking close discard
/// work nobody admitted.
#[cfg(unix)]
fn session_base_standing(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    base: &SessionWorkspaceBase,
) -> Result<(SessionBaseStanding, CurrentAuthorityGenerations)> {
    validate_local_binding_identity(binding, base)?;
    let authority = ActiveRepositoryAuthority::open(binding)?;
    if authority.repository_id != base.repository_id {
        bail!("session base repository identity does not match this repository");
    }
    let lease = authority.manager().read_authority();
    let metadata = lease.metadata();
    let roots = lease.roots();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow!(
                "repository authority has no workspace {}",
                authority.workspace_id
            )
        })?;
    let current = CurrentAuthorityGenerations {
        authority: roots.generation,
        workspace: workspace.generation,
    };
    if roots == &base.authority_roots && workspace == &base.source_workspace {
        return Ok((SessionBaseStanding::Current, current));
    }

    if let Some(receipt) = metadata
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == base.reconcile_operation_id)
    {
        // A persisted receipt names its operation record rather than repeating
        // it (kin-db 0.7.89), so it is validated against the log entry it
        // names rather than against an embedded copy of it. That is the same
        // set of comparisons `RepositoryCommitReceipt::validate` made.
        let operation = metadata
            .operation_log
            .iter()
            .find(|operation| operation.operation_id == receipt.operation_id)
            .ok_or_else(|| {
                anyhow!("session base names an operation this repository's log does not hold")
            })?;
        receipt
            .validate_against(operation)
            .context("validate exact session recovery receipt")?;
        if receipt.repository_id != base.repository_id
            || receipt.roots_before != base.authority_roots
            || &receipt.roots_after != roots
        {
            bail!(
                "session base is stale or tampered: its recovery receipt does not bind the \
                 retained authority roots"
            );
        }
        return Ok((SessionBaseStanding::Reconciled, current));
    }

    validate_superseded_base(metadata, workspace, base)?;
    Ok((SessionBaseStanding::Superseded, current))
}

/// Prove a session base that is no longer current is authentic history.
///
/// The base file is editable, so finding its roots in history does not
/// authenticate the workspace it carries: a forged base could pair genuine
/// roots with any tree. Workspace authority changes only through a committed
/// workspace mutation, and each mutation's compare-and-swap expectation
/// records every stamp of the state it replaced. The first mutation of this
/// workspace after the base's roots therefore names exactly the state the base
/// must carry, and when no later operation touched the workspace, the current
/// workspace is still that state. `SessionWorkspaceBase::validate` has already
/// recomputed the tree, overlay and policy identities from the bodies the base
/// carries, so equal stamps bind those bodies too.
#[cfg(unix)]
fn validate_superseded_base(
    metadata: &kin_db::PersistedRepositoryAuthority,
    current: &kin_model::WorkspaceState,
    base: &SessionWorkspaceBase,
) -> Result<()> {
    let operations = &metadata.operation_log;
    // The open validated the log as one exact root chain, so a bundle names at
    // most one position in it: before the first operation or after one.
    let (next, anchor) = operations
        .iter()
        .enumerate()
        .find_map(|(index, operation)| {
            if index == 0 && operation.roots_before == base.authority_roots {
                Some((0, operation))
            } else if operation.roots_after == base.authority_roots {
                Some((index + 1, operation))
            } else {
                None
            }
        })
        .ok_or_else(|| {
            anyhow!(
                "session base is stale or tampered: its authority roots are not in this \
                 repository's operation history"
            )
        })?;
    let receipt = metadata
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == anchor.operation_id)
        .ok_or_else(|| {
            anyhow!(
                "session base is stale or tampered: the operation holding its authority roots \
                 has no receipt"
            )
        })?;
    receipt
        .validate_against(anchor)
        .context("validate the receipt holding the session base roots")?;

    let workspace_id = base.source_workspace.workspace_id;
    let first_later_mutation = operations[next..].iter().find_map(|operation| {
        operation
            .workspace_mutation
            .as_ref()
            .filter(|mutation| mutation.workspace_id == workspace_id)
    });
    match first_later_mutation {
        Some(mutation) if mutation.expected == workspace_expectation(&base.source_workspace) => {
            Ok(())
        }
        Some(_) => bail!(
            "session base is stale or tampered: the next mutation of its workspace did not \
             start from the workspace state the base carries"
        ),
        None if current == &base.source_workspace => Ok(()),
        None => bail!(
            "session base is stale or tampered: no later operation changed its workspace, and \
             the current workspace differs from the one the base carries"
        ),
    }
}

/// The tree a session asks authority to hold, and the observed changes its
/// filter did not admit.
///
/// A withheld new file is left out, and a withheld change to or removal of a
/// file graph truth holds keeps that file exactly as the base had it, so
/// nothing the policy refuses reaches the transition.
#[cfg(unix)]
fn build_desired_tree(
    base: &SessionWorkspaceBase,
    scan: &SessionScan,
    filter: ObservationFilter,
) -> Result<(ResolvedTree, Vec<WithheldChange>)> {
    let materialized = base
        .materialized_artifact_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let scoped = base.scope.is_some();
    let mut observed = base
        .source_workspace
        .tree
        .artifacts_by_path()
        .filter(|artifact| !materialized.contains(&artifact.artifact_id))
        .map(|artifact| (artifact.path.clone(), artifact.entry))
        .collect::<BTreeMap<_, _>>();
    let mut withheld = scan
        .skipped_generated
        .iter()
        .map(|path| WithheldChange {
            kind: ReconcileChangeKind::Added,
            path: ReconcilePath::from(path),
            reason: WithheldReason::Generated,
        })
        .collect::<Vec<_>>();

    for (path, entry) in &scan.entries {
        let existing = base.source_workspace.tree.artifact_at_path(path);
        match existing {
            Some(existing) if materialized.contains(&existing.artifact_id) => {}
            Some(existing) => {
                bail!(
                    "session observation attempted to mutate unmaterialized artifact {} ({})",
                    path,
                    existing.artifact_id.0
                )
            }
            None if scoped => {
                bail!("scoped session cannot add artifact {path} outside its retained capability")
            }
            None => {}
        }
        let unchanged = existing.is_some_and(|existing| existing.entry == entry.entry);
        let refusal = match filter {
            _ if unchanged => None,
            ObservationFilter::Unfiltered => None,
            ObservationFilter::Policy(SessionWriteBack::ExceptBuildOutputs) => {
                entry.new_file_withheld
            }
            ObservationFilter::Policy(policy) => crate::commands::write_back::agent_withheld(
                path,
                entry.new_file_withheld,
                policy.toolchain(),
            ),
        };
        match (refusal, existing) {
            (None, _) => {
                observed.insert(path.clone(), entry.entry);
            }
            (Some(reason), Some(existing)) => {
                observed.insert(path.clone(), existing.entry);
                withheld.push(WithheldChange {
                    kind: ReconcileChangeKind::Modified,
                    path: ReconcilePath::from(path),
                    reason,
                });
            }
            (Some(reason), None) => withheld.push(WithheldChange {
                kind: ReconcileChangeKind::Added,
                path: ReconcilePath::from(path),
                reason,
            }),
        }
    }

    // An agent's run may remove a manifest it owns, and nothing else: a
    // removed source file stays exactly as the base holds it.
    if let ObservationFilter::Policy(policy) = filter.filter(|policy| policy.manifests_only()) {
        for artifact in base.source_workspace.tree.artifacts_by_path() {
            if !materialized.contains(&artifact.artifact_id)
                || scan.entries.contains_key(&artifact.path)
            {
                continue;
            }
            if let Some(reason) = crate::commands::write_back::agent_withheld(
                &artifact.path,
                None,
                policy.toolchain(),
            ) {
                observed.insert(artifact.path.clone(), artifact.entry);
                withheld.push(WithheldChange {
                    kind: ReconcileChangeKind::Removed,
                    path: ReconcilePath::from(&artifact.path),
                    reason,
                });
            }
        }
    }

    let mut deltas = kin_core::plan_observed_tree_deltas(&base.source_workspace.tree, observed)?;
    // The shared planner retains unique moves and refuses ambiguous identity.
    // New members additionally need session-stable identity so observing the
    // same retained directory twice reconstructs the same transaction.
    for delta in &mut deltas {
        if let TreeDelta::Added { artifact_id, new } = delta {
            *artifact_id = deterministic_added_artifact_id(base.reconcile_operation_id, &new.path);
        }
    }
    let desired = base
        .source_workspace
        .tree
        .apply(&deltas)
        .map_err(|error| anyhow!("build complete desired session tree: {error}"))?;
    Ok((desired, withheld))
}

#[cfg(unix)]
fn deterministic_added_artifact_id(
    operation_id: kin_model::OperationId,
    path: &RepoPath,
) -> ArtifactId {
    ArtifactId(uuid::Uuid::new_v5(&operation_id.as_uuid(), path.as_bytes()))
}

#[cfg(any(unix, test))]
fn enforce_mass_deletion(source_count: usize, deltas: &[TreeDelta], confirmed: bool) -> Result<()> {
    let removed = deltas
        .iter()
        .filter(|delta| matches!(delta, TreeDelta::Removed { .. }))
        .count();
    if !confirmed
        && source_count >= 16
        && removed.saturating_mul(4) > source_count.saturating_mul(3)
    {
        bail!(
            "session reconcile would remove {removed} of {source_count} repository artifacts; \
             repeat with explicit mass-deletion confirmation"
        );
    }
    Ok(())
}

fn reconcile_change(delta: &TreeDelta) -> ReconcileChange {
    match delta {
        TreeDelta::Added { artifact_id, new } => ReconcileChange {
            kind: ReconcileChangeKind::Added,
            artifact_id: *artifact_id,
            old_path: None,
            new_path: Some(ReconcilePath::from(&new.path)),
        },
        TreeDelta::Updated {
            artifact_id,
            old,
            new,
        } => ReconcileChange {
            kind: ReconcileChangeKind::Modified,
            artifact_id: *artifact_id,
            old_path: Some(ReconcilePath::from(&old.path)),
            new_path: Some(ReconcilePath::from(&new.path)),
        },
        TreeDelta::Removed { artifact_id, old } => ReconcileChange {
            kind: ReconcileChangeKind::Removed,
            artifact_id: *artifact_id,
            old_path: Some(ReconcilePath::from(&old.path)),
            new_path: None,
        },
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl EntryIdentity {
    fn from_metadata(metadata: &cap_std::fs::Metadata) -> Self {
        use cap_std::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(unix)]
struct RetainedSession {
    workspace: cap_std::fs::Dir,
    workspace_identity: EntryIdentity,
    kin: cap_std::fs::Dir,
    kin_identity: EntryIdentity,
    runs: cap_std::fs::Dir,
    runs_identity: EntryIdentity,
    session: cap_std::fs::Dir,
    session_identity: EntryIdentity,
    control: cap_std::fs::Dir,
    control_identity: EntryIdentity,
    session_name: std::ffi::OsString,
}

#[cfg(unix)]
impl RetainedSession {
    fn open(layout: &kin_core::KinLayout, session_dir: &Path) -> Result<Self> {
        if !session_dir.is_absolute() || session_dir.parent() != Some(layout.runs_dir().as_path()) {
            bail!(
                "session path must be an absolute direct child of {}",
                layout.runs_dir().display()
            );
        }
        let session_name = session_dir
            .file_name()
            .ok_or_else(|| anyhow!("session path has no leaf name"))?;
        let session_name_text = session_name
            .to_str()
            .ok_or_else(|| anyhow!("session identity must be UTF-8"))?;
        validate_session_leaf(session_name_text)?;

        let workspace = open_root_nofollow(layout.working_dir())?;
        let workspace_identity = directory_identity(&workspace)?;
        let kin = open_directory_nofollow(
            &workspace,
            layout
                .root()
                .file_name()
                .ok_or_else(|| anyhow!("repository control root has no leaf"))?,
        )?;
        let kin_identity = directory_identity(&kin)?;
        let runs = open_directory_nofollow(&kin, std::ffi::OsStr::new("runs"))
            .context("open retained repository session root")?;
        let runs_identity = directory_identity(&runs)?;
        let session = open_directory_nofollow(&runs, session_name)
            .context("open retained exact session directory")?;
        let session_identity = directory_identity(&session)?;
        let control = open_directory_nofollow(&session, std::ffi::OsStr::new(".kin-session"))
            .context("open retained exact session control directory")?;
        let control_identity = directory_identity(&control)?;

        Ok(Self {
            workspace,
            workspace_identity,
            kin,
            kin_identity,
            runs,
            runs_identity,
            session,
            session_identity,
            control,
            control_identity,
            session_name: session_name.to_os_string(),
        })
    }

    fn publication_binding(
        &self,
        base: &SessionWorkspaceBase,
        base_bytes: &[u8],
    ) -> Result<RetainedSessionPublicationBinding> {
        use sha2::{Digest, Sha256};
        let session_leaf = self
            .session_name
            .to_str()
            .ok_or_else(|| anyhow!("session identity must be UTF-8"))?
            .to_owned();
        validate_session_leaf(&session_leaf)?;
        let mut hash = Sha256::new();
        hash.update(b"kin.retained-session.control.unix.v1\0");
        for part in [
            base.repository_id.to_string(),
            base.source_workspace.workspace_id.to_string(),
            session_leaf.clone(),
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part.as_bytes());
        }
        for identity in [
            self.workspace_identity,
            self.kin_identity,
            self.runs_identity,
            self.session_identity,
            self.control_identity,
        ] {
            hash.update(identity.device.to_le_bytes());
            hash.update(identity.inode.to_le_bytes());
        }
        let control_identity = Hash256::from_bytes(hash.finalize().into());
        Ok(RetainedSessionPublicationBinding {
            binding: kin_db::storage::SessionPublicationBinding {
                session_id: format!("retained-{}", hex::encode(control_identity.as_bytes())),
                base_identity: Hash256::from_bytes(Sha256::digest(base_bytes).into()),
                control_identity,
            },
            locator: kin_db::storage::SessionPublicationLocator::RetainedUnixV1 { session_leaf },
        })
    }

    fn read_base(&self) -> Result<Vec<u8>> {
        read_bounded_regular_file(
            &self.control,
            std::ffi::OsStr::new("base.json"),
            MAX_SESSION_BASE_BYTES,
            Some(0o600),
        )
        .context("read exact session base without following links")
    }

    fn scan(
        &self,
        graph_only_paths: &[RepoPath],
        context: &ScanContext<'_>,
        persist_to: Option<&kin_blobs::BlobStore>,
    ) -> Result<SessionScan> {
        let mut scanner = SessionScanner {
            graph_only_paths,
            context,
            entries: BTreeMap::new(),
            skipped_generated: Vec::new(),
            total_bytes: 0,
            directories: 0,
            persist_to,
        };
        scanner.walk(&self.session, &mut Vec::new(), 0)?;
        let paths = scanner.entries.keys().collect::<Vec<_>>();
        let mut byte_paths = paths.iter().map(|path| path.as_bytes()).collect::<Vec<_>>();
        byte_paths.sort_unstable();
        for pair in byte_paths.windows(2) {
            if pair[1] == pair[0]
                || pair[1]
                    .strip_prefix(pair[0])
                    .is_some_and(|suffix| suffix.starts_with(b"/"))
            {
                bail!("session projection contains conflicting byte-exact paths");
            }
        }
        kin_core::validate_source_paths(
            paths
                .iter()
                .copied()
                .filter(|path| path.as_utf8().is_some()),
        )
        .context("validate UTF-8 session projection path aliases")?;
        Ok(SessionScan {
            entries: scanner.entries,
            total_bytes: scanner.total_bytes,
            skipped_generated: scanner.skipped_generated,
        })
    }

    fn revalidate_visible(&self, layout: &kin_core::KinLayout, expected_base: &[u8]) -> Result<()> {
        let workspace = open_root_nofollow(layout.working_dir())?;
        require_directory_identity(&workspace, self.workspace_identity, "repository workspace")?;
        require_directory_identity(
            &self.workspace,
            self.workspace_identity,
            "retained workspace",
        )?;
        let kin = open_directory_nofollow(
            &workspace,
            layout
                .root()
                .file_name()
                .ok_or_else(|| anyhow!("repository control root has no leaf"))?,
        )?;
        require_directory_identity(&kin, self.kin_identity, "repository control root")?;
        require_directory_identity(&self.kin, self.kin_identity, "retained repository control")?;
        let runs = open_directory_nofollow(&kin, std::ffi::OsStr::new("runs"))?;
        require_directory_identity(&runs, self.runs_identity, "repository session root")?;
        require_directory_identity(&self.runs, self.runs_identity, "retained session root")?;
        let session = open_directory_nofollow(&runs, &self.session_name)?;
        require_directory_identity(&session, self.session_identity, "published session")?;
        require_directory_identity(&self.session, self.session_identity, "retained session")?;
        let control = open_directory_nofollow(&session, std::ffi::OsStr::new(".kin-session"))?;
        require_directory_identity(&control, self.control_identity, "session control")?;
        require_directory_identity(&self.control, self.control_identity, "retained control")?;
        if self.read_base()? != expected_base {
            bail!("session base metadata changed during exact observation");
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedEntry {
    entry: TreeEntry,
    /// For a path graph truth does not hold, why no session admits it: a
    /// build output or a generated file. Always `None` for a tracked path.
    new_file_withheld: Option<WithheldReason>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionScan {
    entries: BTreeMap<RepoPath, ObservedEntry>,
    total_bytes: u64,
    /// Generated directories graph truth holds nothing under, which a
    /// filtering scan reports and does not walk.
    skipped_generated: Vec<RepoPath>,
}

/// What a scan knows about the base it observes against.
#[cfg(unix)]
struct ScanContext<'a> {
    base_tree: &'a ResolvedTree,
    /// Every directory that holds a path graph truth tracks, as path bytes.
    tracked_directories: BTreeSet<Vec<u8>>,
    filter: ObservationFilter,
}

#[cfg(unix)]
impl<'a> ScanContext<'a> {
    fn new(base_tree: &'a ResolvedTree, filter: ObservationFilter) -> Self {
        let mut tracked_directories = BTreeSet::new();
        for artifact in base_tree.artifacts() {
            let bytes = artifact.path.as_bytes();
            for (index, byte) in bytes.iter().enumerate() {
                if *byte == b'/' {
                    tracked_directories.insert(bytes[..index].to_vec());
                }
            }
        }
        Self {
            base_tree,
            tracked_directories,
            filter,
        }
    }

    /// Whether a filtering scan leaves this directory unwalked: a generated
    /// name, such as `node_modules` or `target`, with nothing graph truth
    /// tracks beneath it. Its files are never admitted, and walking a
    /// dependency tree or a build directory can cost more entries and bytes
    /// than the whole repository.
    fn skips_directory(&self, path: &RepoPath, name: &std::ffi::OsStr) -> bool {
        use std::os::unix::ffi::OsStrExt as _;
        self.filter.filters()
            && crate::commands::write_back::is_generated_name(name.as_bytes())
            && !self.tracked_directories.contains(path.as_bytes())
    }

    /// Why no session admits the file at `path`, when graph truth does not
    /// hold it.
    fn new_file_withheld(&self, path: &RepoPath, body: Option<&[u8]>) -> Option<WithheldReason> {
        if self.base_tree.artifact_at_path(path).is_some() {
            return None;
        }
        crate::commands::write_back::new_file_withheld(path, body)
    }
}

#[cfg(unix)]
struct SessionScanner<'a> {
    graph_only_paths: &'a [RepoPath],
    context: &'a ScanContext<'a>,
    entries: BTreeMap<RepoPath, ObservedEntry>,
    skipped_generated: Vec<RepoPath>,
    total_bytes: u64,
    directories: usize,
    persist_to: Option<&'a kin_blobs::BlobStore>,
}

#[cfg(unix)]
impl SessionScanner<'_> {
    fn walk(
        &mut self,
        directory: &cap_std::fs::Dir,
        components: &mut Vec<std::ffi::OsString>,
        depth: usize,
    ) -> Result<()> {
        use cap_std::fs::{MetadataExt as _, PermissionsExt as _};
        use std::os::unix::ffi::OsStrExt as _;

        if depth > MAX_SESSION_DEPTH {
            bail!("session projection exceeds directory depth limit {MAX_SESSION_DEPTH}");
        }
        self.directories = self
            .directories
            .checked_add(1)
            .ok_or_else(|| anyhow!("session directory count overflow"))?;
        if self.directories > MAX_SESSION_DIRECTORIES {
            bail!("session projection exceeds directory limit {MAX_SESSION_DIRECTORIES}");
        }

        let directory_metadata_before = directory.dir_metadata()?;
        let directory_before = EntryIdentity::from_metadata(&directory_metadata_before);
        let mut names = directory
            .entries()
            .context("enumerate retained session directory")?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

        for name in names {
            if depth == 0 && name == std::ffi::OsStr::new(".kin-session") {
                continue;
            }
            components.push(name.clone());
            let path = repo_path_from_components(components)?;
            if path.as_bytes().len() > MAX_SESSION_PATH_BYTES {
                bail!("session repository path exceeds {MAX_SESSION_PATH_BYTES} bytes");
            }
            if kin_index::is_repository_control_path(&path) {
                bail!("session projection contains reserved control path {path}");
            }
            if self.is_graph_only_boundary(&path) {
                components.pop();
                continue;
            }

            let metadata = directory
                .symlink_metadata(&name)
                .with_context(|| format!("inspect session entry {path}"))?;
            let identity = EntryIdentity::from_metadata(&metadata);
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && self.context.skips_directory(&path, &name)
            {
                self.skipped_generated.push(path);
            } else if metadata.is_dir() && !metadata.file_type().is_symlink() {
                let child = open_directory_nofollow(directory, &name)
                    .with_context(|| format!("open session directory {path}"))?;
                require_directory_identity(&child, identity, "session directory")?;
                self.walk(&child, components, depth + 1)?;
                let named = directory
                    .symlink_metadata(&name)
                    .with_context(|| format!("revalidate session directory {path}"))?;
                if !named.is_dir()
                    || named.file_type().is_symlink()
                    || EntryIdentity::from_metadata(&named) != identity
                    || named.permissions().mode() != metadata.permissions().mode()
                    || named.mtime() != metadata.mtime()
                    || named.mtime_nsec() != metadata.mtime_nsec()
                    || named.ctime() != metadata.ctime()
                    || named.ctime_nsec() != metadata.ctime_nsec()
                {
                    bail!("session directory {path} changed during exact observation");
                }
                require_directory_identity(&child, identity, "retained session directory")?;
            } else {
                if self.entries.len() >= MAX_SESSION_ENTRIES {
                    bail!("session projection exceeds entry limit {MAX_SESSION_ENTRIES}");
                }
                let (entry, body, new_file_withheld) = if metadata.is_file() {
                    use cap_std::fs::MetadataExt as _;
                    if metadata.nlink() > 1 {
                        bail!("session file {path} has external hard-link aliases");
                    }
                    let body =
                        read_bounded_regular_file(directory, &name, MAX_SESSION_BODY_BYTES, None)
                            .with_context(|| format!("read exact session file {path}"))?;
                    let after = directory
                        .symlink_metadata(&name)
                        .with_context(|| format!("revalidate session file {path}"))?;
                    if !after.is_file()
                        || EntryIdentity::from_metadata(&after) != identity
                        || after.len() != metadata.len()
                        || after.nlink() != metadata.nlink()
                        || after.permissions().mode() != metadata.permissions().mode()
                        || after.mtime() != metadata.mtime()
                        || after.mtime_nsec() != metadata.mtime_nsec()
                        || after.ctime() != metadata.ctime()
                        || after.ctime_nsec() != metadata.ctime_nsec()
                    {
                        bail!("session file {path} changed before or during exact observation");
                    }
                    let executable = metadata.permissions().mode() & 0o111 != 0;
                    let entry = TreeEntry::blob(
                        Hash256::from_bytes(kin_blobs::digest_bytes(&body)),
                        executable,
                    );
                    let withheld = self.context.new_file_withheld(&path, Some(&body));
                    (entry, body, withheld)
                } else if metadata.file_type().is_symlink() {
                    if metadata.nlink() > 1 {
                        bail!("session symlink {path} has external hard-link aliases");
                    }
                    let before = EntryIdentity::from_metadata(&metadata);
                    let target = directory
                        .read_link(&name)
                        .with_context(|| format!("read session symlink {path}"))?;
                    let body = target.as_os_str().as_bytes().to_vec();
                    if body.len() as u64 > MAX_SESSION_BODY_BYTES {
                        bail!("session symlink target {path} exceeds bounded body limit");
                    }
                    let target_again = directory
                        .read_link(&name)
                        .with_context(|| format!("re-read session symlink {path}"))?;
                    let after = directory
                        .symlink_metadata(&name)
                        .with_context(|| format!("revalidate session symlink {path}"))?;
                    if target_again.as_os_str().as_bytes() != body
                        || !after.file_type().is_symlink()
                        || EntryIdentity::from_metadata(&after) != before
                        || after.permissions().mode() != metadata.permissions().mode()
                        || after.len() != metadata.len()
                        || after.nlink() != metadata.nlink()
                        || after.mtime() != metadata.mtime()
                        || after.mtime_nsec() != metadata.mtime_nsec()
                        || after.ctime() != metadata.ctime()
                        || after.ctime_nsec() != metadata.ctime_nsec()
                    {
                        bail!("session symlink {path} changed during exact observation");
                    }
                    let entry =
                        TreeEntry::symlink(Hash256::from_bytes(kin_blobs::digest_bytes(&body)));
                    if path.as_utf8().is_none() {
                        bail!(
                            "byte-exact session symlink path {path} is fail-closed until its \
                             target can be validated without a UTF-8 path conversion"
                        );
                    }
                    kin_core::validate_source_entry(&path, entry, &body)
                        .with_context(|| format!("validate session symlink {path}"))?;
                    let withheld = self.context.new_file_withheld(&path, None);
                    (entry, body, withheld)
                } else {
                    bail!("session path {path} is an unsupported special filesystem entry");
                };
                self.total_bytes = self
                    .total_bytes
                    .checked_add(body.len() as u64)
                    .ok_or_else(|| anyhow!("session observed byte count overflow"))?;
                if self.total_bytes > MAX_SESSION_TOTAL_BYTES {
                    bail!("session projection exceeds total body limit {MAX_SESSION_TOTAL_BYTES}");
                }
                // A file no session admits never reaches ingestion storage: a
                // build leaves binaries of megabytes beside every run.
                let admissible = new_file_withheld.is_none() || !self.context.filter.filters();
                if let Some(blobs) = self.persist_to.filter(|_| admissible) {
                    let digest = blobs
                        .write(&body)
                        .with_context(|| format!("write observed session body for {path}"))?;
                    let expected = entry.blob_identity().ok_or_else(|| {
                        anyhow!("observed session member {path} has no blob identity")
                    })?;
                    if digest.as_bytes() != expected.as_bytes() {
                        bail!(
                            "observed session body for {path} entered CAS as {digest}, expected \
                             {expected}"
                        );
                    }
                    let stored = blobs
                        .read(&digest)
                        .with_context(|| format!("re-read observed session body for {path}"))?;
                    if stored != body {
                        bail!("ingestion CAS changed observed session bytes for {path}");
                    }
                }
                if self
                    .entries
                    .insert(
                        path.clone(),
                        ObservedEntry {
                            entry,
                            new_file_withheld,
                        },
                    )
                    .is_some()
                {
                    bail!("session projection contains duplicate path {path}");
                }
            }
            components.pop();
        }
        let directory_metadata_after = directory.dir_metadata()?;
        if EntryIdentity::from_metadata(&directory_metadata_after) != directory_before
            || directory_metadata_after.permissions().mode()
                != directory_metadata_before.permissions().mode()
            || directory_metadata_after.mtime() != directory_metadata_before.mtime()
            || directory_metadata_after.mtime_nsec() != directory_metadata_before.mtime_nsec()
            || directory_metadata_after.ctime() != directory_metadata_before.ctime()
            || directory_metadata_after.ctime_nsec() != directory_metadata_before.ctime_nsec()
        {
            bail!("retained session directory changed during exact observation");
        }
        Ok(())
    }

    fn is_graph_only_boundary(&self, path: &RepoPath) -> bool {
        self.graph_only_paths.iter().any(|boundary| {
            path == boundary
                || path
                    .as_bytes()
                    .strip_prefix(boundary.as_bytes())
                    .is_some_and(|suffix| suffix.starts_with(b"/"))
        })
    }
}

#[cfg(unix)]
fn repo_path_from_components(components: &[std::ffi::OsString]) -> Result<RepoPath> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut bytes = Vec::new();
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(component.as_bytes());
    }
    RepoPath::from_bytes(bytes).context("encode exact session repository path")
}

#[cfg(unix)]
fn open_root_nofollow(path: &Path) -> Result<cap_std::fs::Dir> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(std::fs::File::from)
    .map(cap_std::fs::Dir::from_std_file)
    .map_err(|error| anyhow!("open {} without following links: {error}", path.display()))
}

#[cfg(unix)]
fn open_directory_nofollow(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::Dir> {
    rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(|fd| cap_std::fs::Dir::from_std_file(fd.into()))
    .map_err(Into::into)
}

#[cfg(unix)]
fn open_regular_file_nofollow(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::File> {
    rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map(|fd| cap_std::fs::File::from_std(std::fs::File::from(fd)))
    .map_err(Into::into)
}

#[cfg(unix)]
fn read_bounded_regular_file(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    limit: u64,
    required_permissions: Option<u32>,
) -> Result<Vec<u8>> {
    use cap_std::fs::{MetadataExt as _, PermissionsExt as _};

    let mut file = open_regular_file_nofollow(parent, name)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() > 1 {
        bail!("entry is not one unaliased regular file");
    }
    if before.len() > limit {
        bail!("regular file exceeds bounded size limit {limit}");
    }
    let identity = EntryIdentity::from_metadata(&before);
    let mode = before.permissions().mode();
    if required_permissions.is_some_and(|required| mode & 0o777 != required) {
        bail!("control file permissions do not match the exact private mode");
    }
    let mut body = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut body)?;
    if body.len() as u64 > limit {
        bail!("regular file exceeded bounded size limit while being read");
    }
    let after = file.metadata()?;
    let named = parent.symlink_metadata(name)?;
    if !after.is_file()
        || !named.is_file()
        || EntryIdentity::from_metadata(&after) != identity
        || EntryIdentity::from_metadata(&named) != identity
        || after.len() != body.len() as u64
        || named.len() != after.len()
        || after.permissions().mode() != mode
        || named.permissions().mode() != mode
        || after.nlink() != before.nlink()
        || named.nlink() != before.nlink()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
        || named.mtime() != before.mtime()
        || named.mtime_nsec() != before.mtime_nsec()
        || named.ctime() != before.ctime()
        || named.ctime_nsec() != before.ctime_nsec()
    {
        bail!("regular file changed identity, kind, mode, or length while being read");
    }
    Ok(body)
}

#[cfg(unix)]
fn directory_identity(directory: &cap_std::fs::Dir) -> Result<EntryIdentity> {
    Ok(EntryIdentity::from_metadata(&directory.dir_metadata()?))
}

#[cfg(unix)]
fn require_directory_identity(
    directory: &cap_std::fs::Dir,
    expected: EntryIdentity,
    label: &str,
) -> Result<()> {
    let actual = directory_identity(directory)?;
    if actual != expected {
        bail!("{label} changed identity during exact session observation");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::ResolvedArtifact;

    #[test]
    fn byte_safe_paths_never_require_lossy_utf8() {
        let utf8 = RepoPath::from_utf8("compose.yaml").unwrap();
        assert_eq!(
            ReconcilePath::from(&utf8),
            ReconcilePath::Utf8("compose.yaml".to_string())
        );
        let raw = RepoPath::from_bytes(b"assets/policy-\xff".to_vec()).unwrap();
        assert_eq!(
            ReconcilePath::from(&raw),
            ReconcilePath::Hex("6173736574732f706f6c6963792dff".to_string())
        );
    }

    /// The scanner returns, and the observation still holds the no-follow
    /// directory capability the walk was taken through. Swapping the session
    /// out from under a completed observation is therefore still detected at
    /// the moment publication asks, not only while the scanner was running.
    #[cfg(unix)]
    #[test]
    fn observation_retains_its_session_capability_after_the_scanner_returns() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("member.txt"), b"admitted\n").unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let blobs = kin_blobs::BlobStore::new(layout.ingest_cas_dir()).unwrap();

        let session_dir = layout.runs_dir().join("session-capability-probe");
        let request = crate::commands::session_workspace::SessionWorkspaceRequest {
            session_dir: session_dir.display().to_string(),
            strategy: None,
            scope: None,
        };
        crate::commands::session_workspace::materialize_session_workspace(
            &layout, &binding, &request,
        )
        .unwrap();

        let observation =
            observe_session_workspace(&layout, &binding, &session_dir, &blobs, false).unwrap();
        observation
            .revalidate_retained_capability(&layout)
            .expect("an untouched session must still satisfy its retained capability");

        // Swap the observed session directory for a different directory of the
        // same name, exactly as a racing writer or a symlink swap would.
        let displaced = layout.runs_dir().join("session-capability-probe-displaced");
        std::fs::rename(&session_dir, &displaced).unwrap();
        std::fs::create_dir(&session_dir).unwrap();
        std::fs::create_dir(session_dir.join(".kin-session")).unwrap();

        let error = observation
            .revalidate_retained_capability(&layout)
            .unwrap_err();
        assert!(
            error.to_string().contains("retained session capability"),
            "{error:#}"
        );
    }

    /// A launch profile is not a session change.
    ///
    /// `kin with --semantic-only` generates the launched assistant's permission
    /// settings before it starts. Those files describe the launch, not the
    /// work, so admitting them would commit an assistant's profile into
    /// repository authority on every clean exit — from the one flag whose
    /// purpose is to keep the graph the only surface the assistant touches.
    ///
    /// The profile therefore lives beside the projection under `.kin/runs/`,
    /// and this asserts the scanner cannot reach it from either direction: the
    /// profile files exist, an ordinary file written inside the projection is
    /// observed, and no profile path appears in the delta.
    #[cfg(unix)]
    #[test]
    fn a_launch_profile_beside_the_projection_is_not_a_session_change() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("member.txt"), b"admitted\n").unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let blobs = kin_blobs::BlobStore::new(layout.ingest_cas_dir()).unwrap();

        let session_dir = layout.runs_dir().join("session-launch-profile-probe");
        let request = crate::commands::session_workspace::SessionWorkspaceRequest {
            session_dir: session_dir.display().to_string(),
            strategy: None,
            scope: None,
        };
        crate::commands::session_workspace::materialize_session_workspace(
            &layout, &binding, &request,
        )
        .unwrap();

        // Written through the production writer, so this binds to where
        // `kin with` actually puts a profile rather than to a fixture of it.
        let adapter = crate::commands::assistant_adapter::adapter_for("claude").unwrap();
        let profile =
            crate::commands::session_run::LaunchProfile::write(&layout.runs_dir(), adapter, false)
                .unwrap();
        let settings = profile.dir().join("semantic-only-settings.json");
        assert!(
            settings.is_file(),
            "the profile must actually be on disk for this assertion to mean anything"
        );
        assert!(
            !profile.dir().starts_with(&session_dir),
            "the profile is inside the projection at {}",
            profile.dir().display()
        );

        // A real working-tree change, so the scanner is demonstrably observing
        // this projection rather than returning an empty delta.
        std::fs::write(session_dir.join("member.txt"), b"edited in session\n").unwrap();

        let observation =
            observe_session_workspace(&layout, &binding, &session_dir, &blobs, false).unwrap();
        let observed = observation
            .deltas()
            .iter()
            .filter_map(|delta| delta.new_state().or_else(|| delta.old_state()))
            .filter_map(|entry| entry.path.as_utf8())
            .collect::<Vec<_>>();

        assert!(
            observed.contains(&"member.txt"),
            "the scanner observed nothing, so this proves nothing: {observed:?}"
        );
        let profile_leaf = profile
            .dir()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap();
        for path in &observed {
            assert!(
                !path.contains(profile_leaf) && !path.contains("semantic-only-settings.json"),
                "a launch profile path reached repository authority: {path}"
            );
        }
    }

    /// A session projection over a fresh, empty repository, for the
    /// write-back tests below. Every file a test writes into it is new.
    #[cfg(unix)]
    fn fresh_session(
        leaf: &str,
    ) -> (
        tempfile::TempDir,
        kin_core::KinLayout,
        kin_core::LocalRepositoryAuthorityBinding,
        kin_blobs::BlobStore,
        PathBuf,
    ) {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let blobs = kin_blobs::BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let session_dir = layout.runs_dir().join(leaf);
        let request = crate::commands::session_workspace::SessionWorkspaceRequest {
            session_dir: session_dir.display().to_string(),
            strategy: None,
            scope: None,
        };
        crate::commands::session_workspace::materialize_session_workspace(
            &layout, &binding, &request,
        )
        .unwrap();
        (repo, layout, binding, blobs, session_dir)
    }

    /// The paths a session observation would admit, as UTF-8 text.
    #[cfg(unix)]
    fn admitted_paths(observation: &SessionReconcileObservation) -> Vec<String> {
        observation
            .deltas()
            .iter()
            .filter_map(|delta| delta.new_state().or_else(|| delta.old_state()))
            .filter_map(|entry| entry.path.as_utf8().map(str::to_string))
            .collect()
    }

    /// The first bytes of a 64-bit Mach-O executable, which is what `go build`
    /// leaves beside `main.go` on macOS, padded to a plausible size.
    #[cfg(unix)]
    fn mach_o_executable() -> Vec<u8> {
        let mut body = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
        body.resize(4096, 0);
        body
    }

    /// A compiled program a command leaves in the session is a build output,
    /// and no session admits one: in a clean `kin exec -- go build ./...` the
    /// only new file is the binary, so nothing is published at all. The
    /// ordinary edit beside it is admitted exactly as before.
    #[cfg(unix)]
    #[test]
    fn a_new_compiled_binary_is_never_admitted_from_a_session() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_repo, layout, binding, blobs, session_dir) = fresh_session("session-build-output");
        let binary = session_dir.join("app");
        std::fs::write(&binary, mach_o_executable()).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(session_dir.join("helper.o"), b"not even an object file").unwrap();
        std::fs::write(session_dir.join("member.txt"), b"edited in session\n").unwrap();

        let observation =
            observe_session_workspace(&layout, &binding, &session_dir, &blobs, false).unwrap();
        let admitted = admitted_paths(&observation);
        assert_eq!(admitted, vec!["member.txt".to_string()], "{admitted:?}");
        assert_eq!(
            withheld_rows(&observation),
            vec![
                (
                    "app".to_string(),
                    ReconcileChangeKind::Added,
                    WithheldReason::BuildOutput
                ),
                (
                    "helper.o".to_string(),
                    ReconcileChangeKind::Added,
                    WithheldReason::BuildOutput
                ),
            ]
        );

        // With only the binary left, the session changes nothing and closes
        // without publishing.
        let (_repo, layout, binding, blobs, session_dir) = fresh_session("session-binary-only");
        std::fs::write(session_dir.join("app"), mach_o_executable()).unwrap();
        let observation =
            observe_session_workspace(&layout, &binding, &session_dir, &blobs, false).unwrap();
        assert!(
            observation.deltas().is_empty(),
            "{:?}",
            admitted_paths(&observation)
        );
        assert_eq!(observation.withheld().len(), 1);
    }

    /// Each withheld change as (path, kind, reason).
    #[cfg(unix)]
    fn withheld_rows(
        observation: &SessionReconcileObservation,
    ) -> Vec<(String, ReconcileChangeKind, WithheldReason)> {
        observation
            .withheld()
            .iter()
            .map(|change| {
                let ReconcilePath::Utf8(path) = &change.path else {
                    panic!("a UTF-8 path");
                };
                (path.clone(), change.kind, change.reason)
            })
            .collect()
    }

    /// A dependency tree or build directory a command creates is reported
    /// once and never walked, so its size cannot push the session past the
    /// observation's entry and byte limits. Ambiguous names that routinely
    /// hold source, such as `build` and `vendor`, are observed as before.
    #[cfg(unix)]
    #[test]
    fn a_generated_directory_the_graph_holds_nothing_under_is_not_walked() {
        let (_repo, layout, binding, blobs, session_dir) = fresh_session("session-generated");
        let modules = session_dir.join("node_modules/left-pad");
        std::fs::create_dir_all(&modules).unwrap();
        std::fs::write(modules.join("index.js"), b"module.exports = 1;\n").unwrap();
        std::fs::create_dir_all(session_dir.join("target/debug")).unwrap();
        std::fs::write(session_dir.join("target/debug/app"), mach_o_executable()).unwrap();
        std::fs::create_dir_all(session_dir.join("vendor/x")).unwrap();
        std::fs::write(session_dir.join("vendor/x/y.go"), b"package x\n").unwrap();

        let observation =
            observe_session_workspace(&layout, &binding, &session_dir, &blobs, false).unwrap();
        assert_eq!(
            admitted_paths(&observation),
            vec!["vendor/x/y.go".to_string()]
        );
        assert_eq!(
            withheld_rows(&observation),
            vec![
                (
                    "node_modules".to_string(),
                    ReconcileChangeKind::Added,
                    WithheldReason::Generated
                ),
                (
                    "target".to_string(),
                    ReconcileChangeKind::Added,
                    WithheldReason::Generated
                ),
            ]
        );
        // Nothing under a skipped directory was read.
        assert_eq!(observation.observed_materialized_artifacts(), 1);
    }

    #[test]
    fn mass_deletion_requires_explicit_confirmation() {
        let source = (0..20)
            .map(|index| {
                ResolvedArtifact::new(
                    ArtifactId::new(),
                    RepoPath::from_utf8(format!("file-{index}")).unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([index as u8; 32]), false),
                )
            })
            .collect::<Vec<_>>();
        let source = ResolvedTree::from_artifacts(source).unwrap();
        let desired =
            ResolvedTree::from_artifacts(source.artifacts().take(4).cloned().collect::<Vec<_>>())
                .unwrap();
        let deltas = kin_core::exact_tree_correction(&source, &desired).unwrap();
        assert!(enforce_mass_deletion(source.len(), &deltas, false).is_err());
        enforce_mass_deletion(source.len(), &deltas, true).unwrap();
    }
}

#[cfg(all(test, unix))]
#[path = "reconcile_session_publication_test.rs"]
mod session_publication_tests;
