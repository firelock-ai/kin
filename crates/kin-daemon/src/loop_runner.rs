// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use kin_index::{
    FileClassification, FileClassifier, FileEvent, FileWatcher, IndexPipeline, IndexedAny,
};
use kin_model::{
    EntityFilter, EntityId, EntityStore, FilePathId, Hash256, RepoPath, ShallowTrackedFile,
    TransactionDelta, TreeDelta, TreeEntry,
};
use tracing::{debug, error, info, warn};

use crate::error::{DaemonError, Result};
use crate::state::{
    ChangeType, DaemonEvent, DaemonState, LspEnrichmentRequest, ProjectionChangedSet, RECON_IDLE,
    RECON_PARKED, RECON_PROCESSING,
};

pub(crate) const DISABLE_FILESYSTEM_RECONCILE_ENV: &str = "KIN_DAEMON_DISABLE_FILESYSTEM_RECONCILE";

fn env_flag_enabled(value: Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Whether this daemon must treat its remote graph as the only write authority.
///
/// This is deliberately independent of `KIN_ALLOW_MASS_DELETION`: graph-only
/// deployments do not scan an empty/projected checkout in the first place, so
/// they never need to authorize destructive filesystem reconciliation.
fn resolve_filesystem_reconcile_disabled(
    storage_backend_graph_authority: bool,
    environment_disabled: bool,
) -> bool {
    storage_backend_graph_authority || environment_disabled
}

pub(crate) fn filesystem_reconcile_disabled_at_startup(
    storage_backend_graph_authority: bool,
) -> bool {
    resolve_filesystem_reconcile_disabled(
        storage_backend_graph_authority,
        env_flag_enabled(std::env::var(DISABLE_FILESYSTEM_RECONCILE_ENV).ok()),
    )
}

/// Configuration for the reconciliation loop.
#[derive(Debug, Clone)]
pub struct LoopConfig {
    /// How often to drain the file watcher (milliseconds).
    pub poll_interval_ms: u64,
    /// Maximum events to process per tick.
    pub batch_size: usize,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 100,
            batch_size: 64,
        }
    }
}

/// Whether `dir` is a bare Git repository, which holds no working copy to
/// reconcile or admit.
///
/// Crate-visible because the on-demand admission seam refuses the same
/// condition. A second copy of the predicate would be a second set of rules to
/// keep in step, and a divergence there would either refuse a store the seam
/// would have admitted or report a skipped pass as a completed one.
pub(crate) fn is_bare_repository(dir: &std::path::Path) -> bool {
    dir.join("config").is_file()
        && dir.join("objects").is_dir()
        && dir.join("refs").is_dir()
        && !dir.join(".git").exists()
}

#[derive(Debug)]
enum AdmittedFileEvent {
    Regular {
        repo_path: RepoPath,
        file_id: Option<FilePathId>,
        content: Vec<u8>,
        blob_hash: kin_blobs::Hash256,
        entry: TreeEntry,
        tree_changed: bool,
    },
    Symlink {
        repo_path: RepoPath,
        file_id: Option<FilePathId>,
        entry: TreeEntry,
        tree_changed: bool,
    },
    Removed {
        repo_path: RepoPath,
        file_id: Option<FilePathId>,
        tree_changed: bool,
    },
    /// Host content at a path repository authority does not track, which the
    /// preceding complete admission deliberately declined to enlarge the
    /// workspace with.
    ///
    /// Distinct from [`Self::Ignored`], which is a path the rules exclude. This
    /// one is admissible content that simply has not been admitted yet, and the
    /// distinction is what the status surfaces report: an ignored path is doing
    /// what was asked of it, an untracked one is waiting for a commit.
    Untracked {
        repo_path: RepoPath,
    },
    Ignored,
}

impl AdmittedFileEvent {
    fn tree_changed(&self) -> bool {
        match self {
            Self::Regular { tree_changed, .. }
            | Self::Symlink { tree_changed, .. }
            | Self::Removed { tree_changed, .. } => *tree_changed,
            Self::Untracked { .. } | Self::Ignored => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnrichmentFacet {
    EntitySource,
    ShallowSyntax,
    StructuredArtifact,
    OpaqueArtifact,
    None,
}

#[derive(Debug, Default)]
pub(crate) struct FacetCleanup {
    pub(crate) removed_entities: Vec<EntityId>,
    changed: bool,
}

#[derive(Debug)]
struct ExactTreeAdmission {
    deltas: Vec<TreeDelta>,
    changed_paths: BTreeSet<RepoPath>,
    semantic_events: Vec<FileEvent>,
    /// The exact admission policy this pass planned against.
    ///
    /// Carried back so the reconcile loop can drop host events for paths the
    /// policy excludes without paying a second authority load per tick. The
    /// loop's copy is therefore one pass old, which is the right staleness for
    /// what it decides: dropping an event is advisory, admission still enforces
    /// the policy exactly, and a rule written this tick takes effect on the
    /// next one instead of on the one that wrote it.
    policy: Option<kin_index::ResolvedAdmissionMatcher>,
    /// The tree transition this admission derived but did not publish, present
    /// only when the caller asked to carry it in its own transaction. Held so
    /// the caller can publish it standalone if its own transaction never
    /// reaches authority.
    deferred_tree: Option<crate::repository_commit::AdmittedWorkspaceTree>,
    /// The pass derived a transition and then stood down for a commit that had
    /// entered the daemon while it worked. Nothing was published and nothing was
    /// applied to the derived graph, so the caller must treat this pass as not
    /// having happened and let the commit admit the working copy itself.
    yielded_to_pending_commit: bool,
}

impl ExactTreeAdmission {
    /// A pass that stood down for a commit already inside the daemon.
    ///
    /// It carries no deltas because it admitted nothing: the transition it
    /// derived was dropped unpublished, so reporting it would name work that
    /// never crossed authority.
    fn yielded(policy: Option<kin_index::ResolvedAdmissionMatcher>) -> Self {
        Self {
            deltas: Vec::new(),
            changed_paths: BTreeSet::new(),
            semantic_events: Vec::new(),
            policy,
            deferred_tree: None,
            yielded_to_pending_commit: true,
        }
    }
}

/// Where an admitted exact tree crosses repository authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreePublication {
    /// The admission publishes its own repository-authority successor. This is
    /// every explicit standalone admission.
    Standalone,
    /// [`Standalone`](Self::Standalone), unless a commit entered the daemon
    /// before this pass reached its publication, in which case the pass stands
    /// down and publishes nothing.
    ///
    /// The ambient watcher path. A commit forces its own complete admission of
    /// the working copy and carries the resulting tree inside the transaction
    /// that publishes its change, so a tick that publishes first buys nothing
    /// and costs one whole O(store) publication.
    StandaloneUnlessACommitIsWaiting,
    /// The caller carries the tree transition in its own transaction. Nothing
    /// is published here, so the caller owns the interval in which the derived
    /// graph holds a tree repository authority has not yet accepted.
    DeferredToCaller,
}

/// State what a watcher could not place inside this repository, or nothing when
/// it has already been stated.
///
/// Once per rise rather than once per tick. The count is a running total, so a
/// loop that re-read it every tick would re-record one unchanged fault forever
/// and bury whatever failed next behind it. A rise is new evidence; a steady
/// count is the same evidence.
///
/// The message names both spellings on purpose. The whole failure is that two
/// correct names for one directory did not compare equal, and a report that
/// gave only one of them would leave a reader unable to see why.
fn events_outside_root_disclosure(
    events: &kin_index::EventsOutsideRoot,
    disclosed: u64,
    working_dir: &Path,
) -> Option<String> {
    if events.count <= disclosed {
        return None;
    }
    let last_path = events
        .last_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "an unrecorded path".to_string());
    Some(format!(
        "{} host event(s) named paths the watcher could not place inside the repository root \
         {}; most recently {last_path}. Nothing those paths changed is admitted from the act of \
         writing it",
        events.count,
        working_dir.display(),
    ))
}

fn repo_path(path: &Path, working_dir: &Path) -> Result<Option<RepoPath>> {
    // Normalize the repository root and the event's nearest existing parent.
    // This treats macOS aliases such as /var and /private/var as the same
    // directory without dereferencing the final entry (which may itself be a
    // dangling symlink, or already removed). Resolving the parent also rejects
    // events that appear lexically beneath the repository but traverse a
    // directory symlink out of it.
    let canonical_root = working_dir.canonicalize().map_err(DaemonError::Io)?;
    let canonical_path =
        kin_index::canonicalize_host_parent_preserving_leaf(path).map_err(DaemonError::Io)?;
    let relative = canonical_path
        .strip_prefix(&canonical_root)
        .map_err(|error| {
            DaemonError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "filesystem event {} escaped repository root {}: {error}",
                    path.display(),
                    working_dir.display()
                ),
            ))
        })?;
    let repo_path = kin_index::repo_path_from_host_relative(relative).map_err(DaemonError::Io)?;
    if kin_index::is_repository_control_path(&repo_path) {
        return Ok(None);
    }
    Ok(Some(repo_path))
}

#[cfg(unix)]
fn symlink_target_bytes(target: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(target.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn symlink_target_bytes(target: &Path) -> std::io::Result<Vec<u8>> {
    target
        .to_str()
        .map(|target| target.as_bytes().to_vec())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "symbolic-link target cannot be represented exactly on this platform",
            )
        })
}

#[cfg(unix)]
fn regular_file_is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn regular_file_is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn semantic_file_id(path: &RepoPath) -> Option<FilePathId> {
    path.as_utf8().map(FilePathId::new)
}

/// Re-read one host entry without mutating blob storage and compare its exact
/// kind, mode, and content identity to graph authority.
///
/// Admission and parser enrichment are intentionally separate phases. This
/// CAS-style check prevents bytes observed after admission from publishing
/// semantic facets against an older tree entry.
fn host_entry_matches_graph(
    state: &DaemonState,
    host_path: &Path,
    repo_path: &RepoPath,
) -> Result<bool> {
    let observed = match std::fs::symlink_metadata(host_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = std::fs::read_link(host_path).map_err(DaemonError::Io)?;
            let bytes = symlink_target_bytes(&target).map_err(DaemonError::Io)?;
            Some(TreeEntry::symlink(Hash256::from_bytes(
                kin_blobs::digest_bytes(&bytes),
            )))
        }
        Ok(metadata) if metadata.file_type().is_file() => {
            let bytes = std::fs::read(host_path).map_err(DaemonError::Io)?;
            Some(TreeEntry::blob(
                Hash256::from_bytes(kin_blobs::digest_bytes(&bytes)),
                regular_file_is_executable(&metadata),
            ))
        }
        Ok(_) => {
            return Err(DaemonError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "repository path changed to an unsupported special entry: {}",
                    host_path.display()
                ),
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(DaemonError::Io(error)),
    };
    let expected = state
        .graph
        .artifact_id_at_path(repo_path)
        .and_then(|artifact_id| state.graph.resolved_artifact(&artifact_id))
        .map(|artifact| artifact.entry);
    if expected.is_none() && observed.is_some() {
        // A file present on disk with no graph entry is what an excluded path
        // looks like once the rules cover it. Retraction untracks rather than
        // deletes, so the file outliving its artifact is the intended end state
        // here and not evidence that the host moved under the admission.
        let ignore = kin_index::RepositoryIgnore::load(state.layout.working_dir())
            .map_err(kin_index::IndexError::from)?;
        if ignore.matches(repo_path) {
            return Ok(true);
        }
    }
    Ok(observed == expected)
}

/// Report whether one host event names a path beneath a graph-only member.
///
/// An unreadable or unmappable event is deliberately reported as not beneath
/// one: the later admission path re-resolves it and owns the refusal, and a
/// transient resolution failure must never silently drop a real observation.
fn event_is_beneath_graph_only_member(state: &DaemonState, event: &FileEvent) -> bool {
    let path = match event {
        FileEvent::Changed(path) | FileEvent::Removed(path) => path,
    };
    match repo_path(path, state.layout.working_dir()) {
        Ok(Some(repo_path)) => is_within_graph_only_member(state, &repo_path).unwrap_or(false),
        Ok(None) | Err(_) => false,
    }
}

/// Whether the graph-owned admission policy excludes the path this event names,
/// and graph truth does not already track it.
///
/// The exact test the walk and the authority boundary both apply, asked of one
/// host notification. `policy` is the last resolved one; before the first
/// admission of a daemon's life there is none and nothing is dropped.
fn event_is_policy_excluded(
    state: &DaemonState,
    policy: Option<&kin_index::ResolvedAdmissionMatcher>,
    event: &FileEvent,
) -> bool {
    let Some(policy) = policy else {
        return false;
    };
    let path = match event {
        FileEvent::Changed(path) | FileEvent::Removed(path) => path,
    };
    let Ok(Some(repo_path)) = repo_path(path, state.layout.working_dir()) else {
        return false;
    };
    if state.graph.artifact_id_at_path(&repo_path).is_some() {
        return false;
    }
    policy.decide(&repo_path, false, false).is_ignored()
}

fn is_within_graph_only_member(state: &DaemonState, path: &RepoPath) -> Result<bool> {
    for artifact in state.graph.resolved_tree().artifacts_by_path() {
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            == kin_core::SourceProjectionDisposition::Materialized
        {
            continue;
        }
        if path == &artifact.path
            || path
                .as_bytes()
                .strip_prefix(artifact.path.as_bytes())
                .is_some_and(|suffix| suffix.starts_with(b"/"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Who a workspace admission the daemon performed on its own is attributed to.
///
/// Not a person, and deliberately not resolved from one. This actor appears only
/// on tree admissions the watch loop and the purge path publish without a
/// caller, so attributing them to whoever last configured a Git identity would
/// name someone who did not perform them.
pub(crate) const DAEMON_ADMISSION_ACTOR: &str = "kin-daemon-admission";

/// Returns the authority generation this admission published, or `None` when
/// the desired tree already matched authority and nothing moved.
pub(crate) fn publish_exact_workspace_tree(
    state: &DaemonState,
    admitted: &crate::repository_commit::AdmittedWorkspaceTree,
) -> Result<Option<u64>> {
    let authority_context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?;
    let started = Instant::now();
    let Some(admission) = crate::repository_commit::publish_workspace_tree(
        state.blobs.as_ref(),
        &authority_context,
        admitted,
        kin_model::OperationId::new(),
        // The daemon's own loop is the actor here, and naming it is a statement
        // rather than a stand-in: nobody typed a command, this publishes no
        // history node and advances no ref, and the workspace transition it
        // records was observed by the watcher. A person's identity would be the
        // fabrication on this path, not the honest answer. Every path that mints
        // a change a person authored takes that person's resolved identity from
        // the caller instead.
        kin_model::AuthorId::new(DAEMON_ADMISSION_ACTOR),
    )?
    else {
        return Ok(None);
    };
    // What this cost is what the reconcile tick is deciding whether to spend, so
    // it is measured here rather than modelled from the store's size.
    state.record_authority_publication(started.elapsed());
    state.record_repository_authority_commit(admission.receipt.generation)?;
    info!(
        workspace = %admission.workspace_id,
        generation = admission.receipt.generation,
        tree_hash = %admission.tree_hash,
        file_deltas = admission.file_count,
        "admitted exact workspace tree into repository authority"
    );
    Ok(Some(admission.receipt.generation))
}

fn invalid_tree_transition(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Graph(kin_db::KinDbError::Model(
        kin_model::ModelError::InvalidOperation(format!(
            "invalid admitted exact-tree transition: {error}"
        )),
    ))
}

/// Refuse one whole observation whose removals were never confirmed.
///
/// This is a refusal of the observation, not of its removal subset: no tree,
/// policy, or graph state derived from it may be published.
fn mass_deletion_refused(removed: u64, total_graph_files: u64) -> DaemonError {
    DaemonError::Graph(kin_db::KinDbError::Model(
        kin_model::ModelError::InvalidOperation(format!(
            "refusing one complete host observation: it removes {removed} of {total_graph_files} \
             graph-known artifacts. No part of an unconfirmed mass deletion is published. Set \
             KIN_ALLOW_MASS_DELETION=1 to confirm an intentional mass deletion"
        )),
    ))
}

/// Read the authority roots an admission plans against and the exact admission
/// policy that authority will judge it by, from one open.
///
/// One open rather than two because the pair has to be coherent: planning a
/// tree against one generation's roots and filtering it through another
/// generation's rules would leave the walk proposing paths the publication is
/// about to refuse, which is the failure this reads the policy to avoid.
///
/// A repository with no local workspace — a hosted snapshot daemon — has no
/// policy to resolve and reports `None`. Nothing is filtered in that case, and
/// nothing is published from a host walk there either.
pub(crate) fn current_authority_admission(
    state: &DaemonState,
) -> Result<(
    kin_model::RootBundle,
    Option<kin_index::ResolvedAdmissionMatcher>,
)> {
    let authority_context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?;
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let roots = authority.read_authority().roots().clone();
    let policy = authority
        .workspace_admission_snapshot(
            authority_context.repository_id(),
            &authority_context.workspace_id(),
        )
        .map_err(DaemonError::Graph)?
        .map(|snapshot| snapshot.matcher);
    Ok((roots, policy))
}

/// What one complete walk declined to observe, taken from its own diagnostics.
///
/// Read off the scan rather than recomputed, so the counts a surface prints and
/// the walk that produced them can never describe different working copies.
fn excluded_host_content(
    scan: &kin_index::CompleteRepositoryScan,
) -> crate::background_work::ExcludedHostContent {
    let diagnostics = scan.diagnostics();
    crate::background_work::ExcludedHostContent {
        ignored: diagnostics.ignored_untracked_entries as u64,
        unsupported: diagnostics.unsupported_untracked_entries as u64,
        policy_excluded: diagnostics.policy_excluded_untracked_entries as u64,
    }
}

/// Say once per pass what the graph-owned policy kept out of it.
///
/// Once per pass and bounded, not once per path: the founder's daemon logged
/// the same refusal continuously, and a walk that meets a churning excluded
/// directory would reproduce that at debug if it named every leaf. The count is
/// complete and the sample is what makes the rule recognizable.
fn announce_policy_exclusions(scan: &kin_index::CompleteRepositoryScan) {
    let excluded = scan.diagnostics().policy_excluded_untracked_entries;
    if excluded == 0 {
        return;
    }
    let sample = scan
        .policy_excluded_paths_sample()
        .iter()
        .map(|path| path.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    debug!(
        count = excluded,
        sample = %sample,
        "the graph-owned admission policy excludes these untracked host paths; \
         they were skipped rather than proposed"
    );
}

/// Report whether one repository path was named by an observation, either
/// exactly or as a descendant of an observed directory.
fn observation_covers_path(observed: &BTreeSet<RepoPath>, path: &RepoPath) -> bool {
    observed.iter().any(|root| {
        path == root
            || path
                .as_bytes()
                .strip_prefix(root.as_bytes())
                .is_some_and(|suffix| suffix.starts_with(b"/"))
    })
}

/// Derive one complete exact-tree transition from the working copy.
///
/// `observation` bounds what may be admitted. `None` is an explicit admission
/// seam such as `/commands/commit`: everything the working copy holds crosses
/// the compare-and-swap, including paths the workspace has never tracked.
///
/// `Some(paths)` is the ambient watcher path, and it is bounded to what the
/// host was observed doing. Only the observed paths and their descendants may
/// move, so one unrelated host event cannot sweep the rest of the working copy
/// in and a single `touch` never costs a complete import. Within that bound an
/// observed path moves whether or not the workspace already tracks it: a file
/// becomes queryable because someone wrote it, not because someone remembered
/// to run a command afterwards.
///
/// What this enlarges is the workspace tree, and only the workspace tree. The
/// publication underneath advances the workspace generation while leaving its
/// head, base target, and base tree hash exactly as they were, so ambient
/// observation moves pending content and never repository history. The commit
/// that later publishes that content is where authorship attaches, and it names
/// what it carried rather than claiming its author wrote it.
///
/// This is a deliberate replacement for an earlier rule under which ambient
/// observation revised graph-owned history but never enlarged it, so a newly
/// written file stayed invisible until someone committed it. That rule cost
/// more than it protected. The transactional write path stages edits against
/// entities and relations that already exist and cannot create a file at a new
/// path at all, which left this the only route by which an agent-authored file
/// could become queryable.
///
/// The scan itself stays complete either way, so a rename keeps one stable
/// artifact identity even when its two halves arrive in different notification
/// batches. Only the planned transition is bounded.
fn exact_tree_admission(
    state: &DaemonState,
    observation: Option<&BTreeSet<RepoPath>>,
    publication: TreePublication,
) -> Result<ExactTreeAdmission> {
    let working_dir = state.layout.working_dir();
    // Read the authority roots the observation is about to be planned against.
    // Publication compare-and-swaps on this bundle, so a repository that moves
    // while the host walk is running fails the whole admission instead of
    // having its desired tree replanned onto the newer authority.
    let (expected_roots, policy) = current_authority_admission(state)?;
    let previous = state.graph.resolved_tree();
    let tracked_paths = previous
        .artifacts_by_path()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let graph_only_paths = crate::graph_only_members::members_of(&previous)?;
    let ignore =
        kin_index::RepositoryIgnore::load(working_dir).map_err(kin_index::IndexError::from)?;
    // A rule that begins matching an already-admitted path retracts it. Ignoring
    // a path is a statement about the semantic index rather than about future
    // walks alone, so the rules are applied to graph-owned tracked identity here
    // and not only to the leaves the walk meets.
    let retracted = kin_index::tracked_paths_retracted_by_ignore(
        &ignore,
        tracked_paths.iter(),
        graph_only_paths.iter(),
    );
    let retracted_paths = retracted.paths().iter().cloned().collect::<BTreeSet<_>>();
    announce_retraction(&retracted);
    // Planned from graph-owned identity rather than inferred from the walk. The
    // observation planner refuses an unmatched removal beside an unmatched
    // addition, because a walk cannot tell that pair apart from a move, and
    // writing a rule produces exactly that pair: `.kinignore` arrives as the
    // addition in the same tick its rule retracts something. The artifact this
    // removes is already known by id, so it is named outright and never has to
    // be guessed at.
    let retraction_deltas = retracted
        .paths()
        .iter()
        .filter_map(|path| previous.artifact_at_path(path))
        .map(|artifact| TreeDelta::Removed {
            artifact_id: artifact.artifact_id,
            old: artifact.located_entry(),
        })
        .collect::<Vec<_>>();
    let planning_base = previous
        .apply(&retraction_deltas)
        .map_err(invalid_tree_transition)?;
    let scanned_tracked = tracked_paths
        .iter()
        .filter(|path| !retracted_paths.contains(*path))
        .collect::<Vec<&RepoPath>>();
    let scan = crate::mcp_commit::timed_commit_phase("scan_working_copy", || {
        kin_index::scan_repository_preserving_graph_only(
            working_dir,
            &ignore,
            policy.as_ref(),
            scanned_tracked.into_iter(),
            graph_only_paths.iter(),
        )
    })
    .map_err(kin_index::IndexError::from)?;
    announce_policy_exclusions(&scan);
    let mut observed =
        crate::mcp_commit::timed_commit_phase("observe_tree_and_stage_blobs", || {
            crate::commit_deltas::observed_tree_from_complete_scan(&state.blobs, &scan, &previous)
        })?;
    if let Some(observation) = observation {
        for artifact in previous.artifacts_by_path() {
            if observation_covers_path(observation, &artifact.path) {
                continue;
            }
            observed.insert(artifact.path.clone(), artifact.entry);
        }
        // What the walk met and authority does not carry divides in two here. A
        // path this observation covers is admitted, which is what makes a file
        // queryable from the act of writing it. The rest is dropped: an event
        // about one path is no evidence about the others, and admitting them
        // anyway would make one host notification pay for a complete import of
        // whatever else happens to be lying in the working copy.
        //
        // The dropped set is exactly what the surfaces report, and it is
        // recoverable rather than refused. Nothing observed those paths
        // arriving, so no later ambient tick reaches them on its own and only an
        // explicit pass will. The scan behind this is complete, so each pass
        // replaces the previous answer instead of adding to it, and the explicit
        // seam below replaces it again the moment one takes what was left.
        //
        // A retired graph-only member takes its host subtree out of the bound
        // for the same reason, and it is the half that cannot be decided from
        // this tree alone. Content beneath a Gitlink was written while the
        // Gitlink still stood, so the events naming it were never observations
        // of this repository's projection. They keep arriving after a transition
        // removes the member, and this tree no longer remembers that it was
        // there, so without the retirement they read as ordinary new files and
        // one branch switch leaves the workspace ahead of the base it was just
        // made level with. The paths stay in the untracked report either way, so
        // an explicit seam still sweeps them and says what it took.
        //
        // The retired set is read once for the whole pass rather than per path.
        // It is small and usually empty, but `observed` is the working copy.
        let retired = state.retired_graph_only_members.snapshot();
        let admissible = |path: &RepoPath| {
            observation_covers_path(observation, path)
                && !crate::graph_only_members::covered_by(&retired, path)
        };
        state
            .background_work
            .reconcile()
            .record_untracked_observation(
                observed.entries().keys().filter(|path| {
                    previous.artifact_id_at_path(path).is_none() && !admissible(path)
                }),
                excluded_host_content(&scan),
            );
        observed.retain(|path, _| previous.artifact_id_at_path(path).is_some() || admissible(path));
    }
    // A bounded tick re-inserts every tracked path its observation did not
    // cover, which would restore the paths the rules just retracted. Editing
    // `.kinignore` is exactly that shape of event, so without this the surface a
    // user writes the rule on is the one surface where it never takes effect.
    observed.retain(|path, _| !retracted_paths.contains(path));
    let mut deltas = retraction_deltas;
    deltas.extend(kin_core::plan_observed_tree_deltas(
        &planning_base,
        observed.entries().clone(),
    )?);

    let removed_count = deltas
        .iter()
        .filter(|delta| matches!(delta, TreeDelta::Removed { .. }))
        .count() as u64;
    let allow_mass_deletion = std::env::var("KIN_ALLOW_MASS_DELETION")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false);
    if should_block_mass_deletion(removed_count, previous.len() as u64, allow_mass_deletion) {
        state.mass_deletion_blocked.store(true, Ordering::Relaxed);
        // One host walk is one observation. Suppressing only its removals and
        // replanning would publish the additions, modifications, and derived
        // admission-policy state that the same unconfirmed observation carried,
        // which is a partial publication of a transition the operator refused.
        // The whole observation is dropped instead; nothing crosses authority
        // and graph truth is retained until the deletion is confirmed.
        return Err(mass_deletion_refused(removed_count, previous.len() as u64));
    }
    state.mass_deletion_blocked.store(false, Ordering::Relaxed);

    let mut changed_paths = BTreeSet::new();
    let mut semantic_events = Vec::new();
    for delta in &deltas {
        if let Some(old) = delta.old_state() {
            changed_paths.insert(old.path.clone());
            if delta.new_state().is_none_or(|new| new.path != old.path) {
                if let Ok(path) = kin_index::host_path_from_repo_path(working_dir, &old.path) {
                    semantic_events.push(FileEvent::Removed(path));
                }
            }
        }
        if let Some(new) = delta.new_state() {
            changed_paths.insert(new.path.clone());
            if let Ok(path) = kin_index::host_path_from_repo_path(working_dir, &new.path) {
                semantic_events.push(FileEvent::Changed(path));
            }
        }
    }

    let mut deferred_tree = None;
    if !deltas.is_empty() {
        let desired_tree = previous.apply(&deltas).map_err(invalid_tree_transition)?;
        // Repository authority moves first. The in-memory graph is a derived
        // staging/query view and must never acknowledge dirty file truth that
        // has not crossed the repository-v6 compare-and-swap. The scanner's
        // completion proof and the planning base travel with the tree so
        // publication can verify both rather than trust the caller.
        let admitted = crate::repository_commit::AdmittedWorkspaceTree::from_complete_observation(
            observed.completion(),
            expected_roots,
            previous.clone(),
            desired_tree,
        );
        // A deferring caller publishes this same transition inside its own
        // transaction, so authority still moves before anything outside the
        // caller can observe the graph: the coordination gate the caller holds
        // spans this admission and that publication, and the caller restores
        // this ordering by publishing the deferred tree if its transaction
        // never reaches authority. What it buys is one repository-authority
        // successor for the whole commit rather than two, each of which
        // prepares and persists the complete store.
        //
        // A transition that moves a graph-only repository member is never
        // deferred. An exact-source projection may not carry one, so the
        // caller's transaction would refuse it; this publishes it here exactly
        // as a standalone admission does.
        let defer = publication == TreePublication::DeferredToCaller
            && !transition_touches_graph_only_member(&deltas)?;
        // The last point at which standing down is free, and the last one at
        // which it is possible. Everything above derived a transition and wrote
        // nothing that outlives this call; everything below crosses
        // repository authority or advances the derived graph, and a pass that
        // stopped between them would leave the graph carrying a tree authority
        // never accepted.
        //
        // The commit that this defers to may have arrived a moment ago, while
        // this pass was walking the working copy. It will admit the same paths
        // itself, because its own admission is unbounded by any observation.
        // Nothing is lost by dropping this transition on the floor, and the
        // whole point is that the commit publishes once for both.
        if publication == TreePublication::StandaloneUnlessACommitIsWaiting {
            state
                .pending_commits
                .refresh_approaching(state.layout.root());
        }
        let yields = publication == TreePublication::StandaloneUnlessACommitIsWaiting
            && state.pending_commits.any();
        if defer {
            deferred_tree = Some(admitted);
        } else if yields {
            debug!(
                deltas = deltas.len(),
                "standing this ambient admission down for a commit already inside the daemon; \
                 its transaction carries the tree"
            );
            return Ok(ExactTreeAdmission::yielded(policy));
        } else {
            // The phase stays on the standalone path, which is the path that
            // still spends it. A deferring caller reports its own publication
            // instead, so a collapsed commit names no admission publication at
            // all, which is what the phase table should show.
            let _ = crate::mcp_commit::timed_commit_phase("publish_workspace_admission", || {
                publish_exact_workspace_tree(state, &admitted)
            })?;
        }
        // Authority has committed the removal, so the entities derived from
        // those paths go before the graph is asked to match. kin-db refuses a
        // tree transition that leaves an entity on a path the staged tree no
        // longer carries, and it is right to: an artifact that stops existing
        // while its entities keep ranking is the exposure this ordering exists
        // to prevent.
        evict_enrichment_for_removed_paths(state, &deltas)?;
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: deltas.clone(),
                ..TransactionDelta::default()
            })
            .map_err(|error| name_stranded_endpoint_refusal(DaemonError::Graph(error), &deltas))?;
    }

    if observation.is_none() {
        // An explicit seam admits every host path the complete walk met, so
        // once it publishes, nothing the working copy holds is untracked. Say
        // so here rather than waiting for the next ambient tick: a commit
        // produces no watcher event of its own, since the daemon's own writes
        // land under `.kin` and the watcher drops control paths before they
        // reach the queue. On a quiescent working copy the next tick never
        // arrives, and the surfaces would keep naming a path this admission
        // just made queryable. It is recorded after publication, not before, so
        // a refused observation leaves a still-true record standing.
        //
        // What the walk declined to observe is still declined, and this pass
        // measured it as recently as any ambient one, so it is republished
        // rather than cleared.
        state
            .background_work
            .reconcile()
            .record_untracked_observation(
                std::iter::empty::<&RepoPath>(),
                excluded_host_content(&scan),
            );
        // The same pass took whatever the retirements were holding back, so they
        // have served their purpose. A caller who explicitly admits the subtree
        // under a removed Gitlink has said outright that the content is theirs,
        // and ambient observation resumes over it from here.
        state.retired_graph_only_members.clear();
    }

    Ok(ExactTreeAdmission {
        deltas,
        changed_paths,
        semantic_events: dedup_file_events(semantic_events),
        policy,
        deferred_tree,
        yielded_to_pending_commit: false,
    })
}

/// Run one ambient reconcile round's admission the way the loop runs it, and
/// report whether it stood down for a commit.
///
/// The loop itself is a watcher, a batcher, and a retry ladder wrapped around
/// this one call, none of which the commit race is about. This is the seam a
/// test drives so the race can be composed in a fixed order instead of hoped
/// for.
// Gated to match its only caller, the unix-only race test in `api`: a helper
// whose callers are platform-gated is dead code on every other platform, and
// the CI gate compiles with `-D warnings`.
#[cfg(all(test, unix))]
pub(crate) fn ambient_admission_for_test(
    state: &DaemonState,
    observation: &BTreeSet<RepoPath>,
) -> Result<bool> {
    exact_tree_admission(
        state,
        Some(observation),
        TreePublication::StandaloneUnlessACommitIsWaiting,
    )
    .map(|admission| admission.yielded_to_pending_commit)
}

/// Report whether one planned exact-tree transition moves a repository member
/// that has no host representation.
///
/// An exact-source projection refuses to carry a graph-only transition, so a
/// caller that means to fold the tree into its own transaction has to know
/// before it plans rather than discover it at the projection boundary.
fn transition_touches_graph_only_member(deltas: &[TreeDelta]) -> Result<bool> {
    for delta in deltas {
        for located in [delta.old_state(), delta.new_state()].into_iter().flatten() {
            if kin_core::source_projection_disposition(&located.path, located.entry)?
                != kin_core::SourceProjectionDisposition::Materialized
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Classify one host event against exact repository-tree truth that has
/// already been admitted, before attempting any enrichment.
///
/// `admitted_paths` are the paths the preceding complete-scan transaction moved.
/// This function never publishes: exact tree truth reaches repository authority
/// only through [`exact_tree_admission`], which carries the scanner's completion
/// proof. A per-event publication seam here would be a raw-filesystem rebuild of
/// authority with no proof that the walk behind it ever completed.
///
/// A removal notification is reclassified as a change when the directory
/// entry exists again (including a dangling symlink); a change notification is
/// reclassified as a removal when the entry disappeared before processing.
fn admit_file_event_with_exact_tree(
    state: &DaemonState,
    event: &FileEvent,
    admitted_paths: &BTreeSet<RepoPath>,
) -> Result<AdmittedFileEvent> {
    let path = match event {
        FileEvent::Changed(path) | FileEvent::Removed(path) => path,
    };
    let working_dir = state.layout.working_dir();
    let Some(repo_path) = repo_path(path, working_dir)? else {
        return Ok(AdmittedFileEvent::Ignored);
    };
    if is_within_graph_only_member(state, &repo_path)? {
        debug!(
            path = %repo_path,
            "ignoring host event beneath graph-only repository member"
        );
        return Ok(AdmittedFileEvent::Ignored);
    }
    let file_id = semantic_file_id(&repo_path);
    let in_graph = state.graph.artifact_id_at_path(&repo_path).is_some();
    let tracked = in_graph || admitted_paths.contains(&repo_path);
    let ignore =
        kin_index::RepositoryIgnore::load(working_dir).map_err(kin_index::IndexError::from)?;
    if !in_graph && ignore.matches(&repo_path) {
        // The rules exclude this path and graph truth no longer carries it. If
        // the preceding transition is what took it out, it is a retraction and
        // its enrichment has to go with it. Reading the host here instead would
        // find the file still present, classify it as an ordinary change, and
        // re-enrich a path the repository just stopped tracking.
        if admitted_paths.contains(&repo_path) {
            return Ok(AdmittedFileEvent::Removed {
                repo_path,
                file_id,
                tree_changed: true,
            });
        }
        return Ok(AdmittedFileEvent::Ignored);
    }

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let tree_changed = admitted_paths.contains(&repo_path);
            return Ok(AdmittedFileEvent::Removed {
                repo_path,
                file_id,
                tree_changed,
            });
        }
        Err(error) => return Err(DaemonError::Io(error)),
    };

    let file_type = metadata.file_type();
    if !tracked && (file_type.is_file() || file_type.is_symlink()) {
        // Admissible host content the complete admission that just ran did not
        // carry. An observed new path is admitted by that pass and reaches here
        // tracked, so what is left is content the walk never met: a file created
        // after its own directory was walked, or one whose notification arrived
        // without it. Enriching it is not available either, because the
        // revalidation below compares host bytes against the tree entry
        // authority holds and authority holds none, so this path can only ever
        // fail that comparison.
        //
        // It is declined here rather than deferred because a deferral would be a
        // promise the loop cannot keep. Every retry costs one complete exact-tree
        // admission over the whole working copy and arrives at the identical
        // refusal, so the ladder never converges: the backlog stays non-empty for
        // as long as the daemon lives, reconciliation_status never returns to
        // idle, backlog_age climbs without bound, and the store spends a core
        // rescanning itself while admitting nothing. Declining once, out loud, is
        // what keeps that shut.
        return Ok(AdmittedFileEvent::Untracked { repo_path });
    }
    let (content, blob_hash, entry, is_symlink) = if file_type.is_symlink() {
        let target = std::fs::read_link(path).map_err(DaemonError::Io)?;
        let content = symlink_target_bytes(&target).map_err(DaemonError::Io)?;
        let blob_hash = state.blobs.write(&content)?;
        let content = state.blobs.read(&blob_hash)?;
        (
            content,
            blob_hash,
            TreeEntry::symlink(Hash256::from_bytes(blob_hash.0)),
            true,
        )
    } else if file_type.is_file() {
        let content = std::fs::read(path).map_err(DaemonError::Io)?;
        let blob_hash = state.blobs.write(&content)?;
        let content = state.blobs.read(&blob_hash)?;
        (
            content,
            blob_hash,
            TreeEntry::blob(
                Hash256::from_bytes(blob_hash.0),
                regular_file_is_executable(&metadata),
            ),
            false,
        )
    } else {
        if !tracked {
            warn!(
                path = %path.display(),
                "skipping untracked special filesystem entry outside Kin's representable tree"
            );
            return Ok(AdmittedFileEvent::Ignored);
        }
        return Err(DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "tracked repository path changed to an unsupported special entry: {}",
                path.display()
            ),
        )));
    };

    let tree_changed = admitted_paths.contains(&repo_path);

    if is_symlink {
        Ok(AdmittedFileEvent::Symlink {
            repo_path,
            file_id,
            entry,
            tree_changed,
        })
    } else {
        Ok(AdmittedFileEvent::Regular {
            repo_path,
            file_id,
            content,
            blob_hash,
            entry,
            tree_changed,
        })
    }
}

#[cfg(test)]
fn admit_file_event(state: &DaemonState, event: &FileEvent) -> Result<AdmittedFileEvent> {
    // Mirror production ordering: one complete-scan transaction crosses
    // authority first, then host events are classified against what it moved.
    let admission = exact_tree_admission(state, None, TreePublication::Standalone)?;
    admit_file_event_with_exact_tree(state, event, &admission.changed_paths)
}

/// Mirror the reconcile loop's ambient tick rather than the explicit seam.
///
/// The distinction is the whole subject of the untracked-path tests: the same
/// host event reaches a different verdict depending on whether an explicit
/// admission asked for the working copy or a watcher merely noticed it.
#[cfg(test)]
fn admit_file_event_ambient(state: &DaemonState, event: &FileEvent) -> Result<AdmittedFileEvent> {
    let (FileEvent::Changed(path) | FileEvent::Removed(path)) = event;
    let observation = repo_path(path, state.layout.working_dir())?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let admission = exact_tree_admission(state, Some(&observation), TreePublication::Standalone)?;
    admit_file_event_with_exact_tree(state, event, &admission.changed_paths)
}

/// Run one ambient watcher tick over a single host path and keep only what it
/// left behind.
///
/// For tests in other modules that need the state a watcher produces rather
/// than the verdict it reached, so the pending content a commit folds can come
/// from the real path instead of from a delta assembled to resemble it.
#[cfg(test)]
pub(crate) fn admit_one_ambient_host_event(state: &DaemonState, path: PathBuf) -> Result<()> {
    admit_file_event_ambient(state, &FileEvent::Changed(path))?;
    Ok(())
}

fn clear_incompatible_facets(
    state: &DaemonState,
    file_id: &FilePathId,
    keep: EnrichmentFacet,
) -> Result<FacetCleanup> {
    clear_incompatible_facets_in(state.graph.as_ref(), file_id, keep)
}

/// The same cleanup against a graph named outright rather than reached through
/// the daemon's live state.
///
/// The MCP transaction planner needs it against the PROSPECTIVE graph it is
/// building, which is not the live one and must not be, because a transaction
/// that fails to plan may not have touched anything a query can see. Naming the
/// graph is what lets one definition of "retire this file's enrichment" serve
/// both the watcher seam and the planner, so the two cannot drift into
/// disagreeing about what a retirement takes with it.
pub(crate) fn clear_incompatible_facets_in(
    graph: &kin_db::InMemoryGraph,
    file_id: &FilePathId,
    keep: EnrichmentFacet,
) -> Result<FacetCleanup> {
    let mut cleanup = FacetCleanup::default();

    if keep != EnrichmentFacet::EntitySource {
        let entities = graph.query_entities(&EntityFilter {
            file_path: Some(file_id.clone()),
            ..Default::default()
        })?;
        cleanup.removed_entities = entities.into_iter().map(|entity| entity.id).collect();
        graph.remove_entities_batch(&cleanup.removed_entities)?;
        cleanup.changed |= !cleanup.removed_entities.is_empty();
        if graph.get_file_layout(file_id)?.is_some() {
            graph.delete_file_layout(file_id)?;
            cleanup.changed = true;
        }
    }

    if keep != EnrichmentFacet::ShallowSyntax && graph.get_shallow_file(file_id)?.is_some() {
        graph.delete_shallow_file(file_id)?;
        cleanup.changed = true;
    }
    if keep != EnrichmentFacet::StructuredArtifact
        && graph.get_structured_artifact(file_id)?.is_some()
    {
        graph.delete_structured_artifact(file_id)?;
        cleanup.changed = true;
    }
    if keep != EnrichmentFacet::OpaqueArtifact && graph.get_opaque_artifact(file_id)?.is_some() {
        graph.delete_opaque_artifact(file_id)?;
        cleanup.changed = true;
    }

    Ok(cleanup)
}

/// Retracted paths named in one operator-facing line, with a bounded sample.
///
/// A retraction removes graph-owned identity, so it is never allowed to happen
/// quietly. A rule broad enough to cover a source tree has to be visible in the
/// log the moment it takes effect rather than discovered later as a gap in
/// query results.
const ANNOUNCED_RETRACTION_SAMPLE: usize = 20;

fn announce_retraction(retracted: &kin_index::IgnoredTrackedPaths) {
    if retracted.is_empty() {
        return;
    }
    let sample = retracted
        .paths()
        .iter()
        .take(ANNOUNCED_RETRACTION_SAMPLE)
        .map(RepoPath::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    warn!(
        retracted = retracted.len(),
        tracked = retracted.tracked_total(),
        retained = retracted.retained_total(),
        sample = %sample,
        "ignore rules now cover tracked paths; retracting them from graph truth with their \
         entities and embeddings. The files stay on disk."
    );
}

/// Retire every relation bound to an artifact node that is leaving the tree.
///
/// An artifact-class endpoint is not reachable from any entity, so clearing a
/// path's entities leaves these edges standing: the file-level `Imports` and
/// `Includes` edges the cross-file linker mints, its parse-coverage self-loop,
/// and the `DerivedFrom` edges projection markers produce. kin-db validates
/// every relation the graph holds against the staged tree on each transaction,
/// so one surviving edge makes the removal of its artifact fail with
/// `transaction relation <id> has unadmitted source endpoint artifact:<id>`,
/// and it fails the whole transaction rather than the one edge. That is how a
/// deleted file could take the entire commit path down with it: nothing else
/// collects these, and only emptying the file first, which routes the retirement
/// through the linker's own re-derivation, ever cleared them.
///
/// Returns the relations retired, so a caller can report what a removal took.
fn retire_artifact_node_relations(
    graph: &kin_db::InMemoryGraph,
    artifact_id: kin_model::ArtifactId,
) -> Result<Vec<kin_model::RelationId>> {
    let node = kin_model::GraphNodeId::Artifact(artifact_id);
    let bound = graph.get_all_relations_for_node(&node)?;
    if bound.is_empty() {
        return Ok(Vec::new());
    }
    let retired: Vec<kin_model::RelationId> = bound.iter().map(|relation| relation.id).collect();
    let borrowed: Vec<&kin_model::RelationId> = retired.iter().collect();
    graph.remove_relations_batch(&borrowed)?;
    debug!(
        ?artifact_id,
        retired = retired.len(),
        "retired the relations bound to a departing artifact node"
    );
    Ok(retired)
}

/// Say what a refused tree transition was about when kin-db reports one of its
/// relations still naming a node the staged tree no longer carries.
///
/// The storage message names a relation uuid and an artifact uuid and nothing
/// else. Neither maps to a file, the refusal is of the whole transaction rather
/// than of the edge, and the surface a user meets is a commit that cannot run at
/// all. Name the paths this transition drops and the two-step retirement that
/// clears the edges, so the message a user reads is about their repository
/// rather than about kin's internals.
pub(crate) fn name_stranded_endpoint_refusal(
    error: DaemonError,
    deltas: &[TreeDelta],
) -> DaemonError {
    let message = error.to_string();
    if !message.contains("unadmitted source endpoint")
        && !message.contains("unadmitted destination endpoint")
    {
        return error;
    }
    let removed = deltas
        .iter()
        .filter_map(|delta| match delta {
            TreeDelta::Removed { old, .. } => Some(old.path.to_string()),
            TreeDelta::Added { .. } | TreeDelta::Updated { .. } => None,
        })
        .collect::<Vec<_>>();
    let dropped = if removed.is_empty() {
        "this transition".to_string()
    } else {
        removed.join(", ")
    };
    DaemonError::IncompatibleRepo(format!(
        "refusing to drop {dropped}: the graph still holds a relation whose endpoint is the \
         artifact being removed, and kin-db refuses a transition that strands one ({message}). \
         fix: empty the file and commit, which retires the edges through the linker, then delete \
         the empty file and commit again. Report this: a removal is supposed to collect these \
         edges itself"
    ))
}

/// Remove the enrichment derived from every path a tree transition drops.
///
/// Entities, their relations, and their text and vector index presence are what
/// make a path rankable, and none of it is inferred from the tree: kin-db keeps
/// entity removal an explicit transition and refuses a tree change that would
/// strand one. Clearing here is what lets a removal of any kind, a deleted file
/// or a newly ignored one, take the whole artifact out rather than only its
/// tree entry.
///
/// Artifact-class edges go with it. They have no entity endpoint, so the entity
/// cleanup below cannot see them, and kin-db refuses the tree transition that
/// strands one exactly as it refuses a stranded entity.
pub(crate) fn evict_enrichment_for_removed_paths(
    state: &DaemonState,
    deltas: &[TreeDelta],
) -> Result<()> {
    for delta in deltas {
        let TreeDelta::Removed { old, .. } = delta else {
            continue;
        };
        retire_artifact_node_relations(state.graph.as_ref(), delta.artifact_id())?;
        let Some(file_id) = semantic_file_id(&old.path) else {
            continue;
        };
        let cleanup = clear_incompatible_facets(state, &file_id, EnrichmentFacet::None)?;
        for id in cleanup.removed_entities {
            state.emit_event(DaemonEvent::EntityChanged {
                entity_id: id,
                change_type: ChangeType::Deleted,
                file_path: Some(file_id.0.clone()),
                session_id: None,
            });
        }
    }
    Ok(())
}

/// Clear UTF-8-only enrichment for an artifact the exact-tree transaction has
/// already removed. Non-UTF-8 artifacts have no `FilePathId` enrichment
/// surface and need no cleanup.
fn finalize_tree_removal(
    state: &DaemonState,
    file_id: Option<&FilePathId>,
    tree_changed: bool,
) -> Result<FacetCleanup> {
    if !tree_changed {
        return Ok(FacetCleanup::default());
    }
    match file_id {
        Some(file_id) => clear_incompatible_facets(state, file_id, EnrichmentFacet::None),
        None => Ok(FacetCleanup::default()),
    }
}

fn shallow_tracked_file(shallow: kin_parser::ShallowFile) -> ShallowTrackedFile {
    ShallowTrackedFile {
        file_id: shallow.file_id,
        language_hint: shallow.language_hint.unwrap_or_default(),
        declaration_count: shallow.declarations.len(),
        import_count: shallow.imports.len(),
        syntax_hash: shallow.fingerprint.syntax_hash,
        signature_hash: shallow.fingerprint.signature_hash,
        declaration_names: shallow
            .declarations
            .into_iter()
            .map(|declaration| declaration.name)
            .collect(),
        import_paths: shallow
            .imports
            .into_iter()
            .map(|import| import.raw_path)
            .collect(),
    }
}

fn persist_non_entity_enrichment(
    state: &DaemonState,
    indexed: IndexedAny,
) -> Result<(FilePathId, FacetCleanup)> {
    match indexed {
        IndexedAny::EntitySource(_) => Err(DaemonError::Io(std::io::Error::other(
            "entity source reached non-entity enrichment path",
        ))),
        IndexedAny::ShallowSyntax(shallow) => {
            let shallow = shallow_tracked_file(shallow);
            let cleanup =
                clear_incompatible_facets(state, &shallow.file_id, EnrichmentFacet::ShallowSyntax)?;
            state.graph.upsert_shallow_file(&shallow)?;
            Ok((shallow.file_id, cleanup))
        }
        IndexedAny::StructuredArtifact(artifact) => {
            let cleanup = clear_incompatible_facets(
                state,
                &artifact.file_id,
                EnrichmentFacet::StructuredArtifact,
            )?;
            state.graph.upsert_structured_artifact(&artifact)?;
            Ok((artifact.file_id, cleanup))
        }
        IndexedAny::OpaqueArtifact(artifact) => {
            let cleanup = clear_incompatible_facets(
                state,
                &artifact.file_id,
                EnrichmentFacet::OpaqueArtifact,
            )?;
            state.graph.upsert_opaque_artifact(&artifact)?;
            Ok((artifact.file_id, cleanup))
        }
    }
}

/// Create the missing non-entity enrichment records for the current resolved
/// tree, reading bodies from the repository CAS.
///
/// Bulk admission (`kin init` importing a Git repository) derives entities for
/// parser-supported sources and stops there: no shallow, structured, or opaque
/// record is written for any other tracked file. Every downstream artifact
/// surface keys on those records — `artifact_count()`, the artifact embedding
/// queue, the text index that feeds lexical artifact candidacy — so a store
/// born from bulk admission reports "+0 artifacts" on `kin embed` and can never
/// rank an artifact, while `kin status` counts the same files as tracked. The
/// live reconcile loop only enriches paths that produce file events, which an
/// unchanged imported tree never does.
///
/// This pass is strictly additive: a path is skipped when any enrichment facet
/// already exists for it (including an entity-source layout), when its current
/// bytes classify as entity source, or when its tree entry carries no blob
/// body. It never deletes or replaces a facet, so drift between an existing
/// record and tree truth stays the reconcile loop's job. Bodies come from the
/// repository CAS, never from the working filesystem.
///
/// Returns how many records were created. Callers that receive a nonzero count
/// own bumping the state version so the records persist with the next snapshot.
///
/// Gated with its only runtime caller, the embed request handler: a build
/// without embedding support has no surface that asks for this coverage, and
/// an uncalled function fails the deny-warnings build on exactly those
/// feature subsets.
#[cfg(feature = "embeddings")]
pub(crate) fn ensure_non_entity_enrichment_coverage(state: &DaemonState) -> Result<usize> {
    let tree = state.graph.resolved_tree();
    let pipeline = IndexPipeline::new();
    let mut created = 0usize;
    let mut unreadable = 0usize;

    for artifact in tree.artifacts() {
        if !matches!(artifact.entry, TreeEntry::Blob { .. }) {
            continue;
        }
        let Some(hash) = artifact.entry.blob_identity() else {
            continue;
        };
        let Some(path) = artifact.path.as_utf8() else {
            // Non-UTF-8 paths stay byte-exact tree truth with no UTF-8
            // enrichment surface, same as the live reconcile loop.
            continue;
        };
        let file_id = FilePathId::new(path);

        if state.graph.get_shallow_file(&file_id)?.is_some()
            || state.graph.get_structured_artifact(&file_id)?.is_some()
            || state.graph.get_opaque_artifact(&file_id)?.is_some()
            || state.graph.get_file_layout(&file_id)?.is_some()
        {
            continue;
        }

        let content = match state.blobs.read(&hash) {
            Ok(content) => content,
            Err(error) => {
                // A missing derived body must not fail daemon startup; CAS
                // hydration owns repairing it, and the next pass retries.
                unreadable += 1;
                debug!(
                    file = %file_id,
                    error = %error,
                    "enrichment coverage pass could not read tracked body from CAS"
                );
                continue;
            }
        };

        if FileClassifier::classify_with_content(Path::new(path), &content)
            == FileClassification::EntitySource
        {
            continue;
        }

        match pipeline.index_any_content(&file_id, &content, hash) {
            Ok(indexed) => match persist_non_entity_enrichment(state, indexed) {
                Ok(_) => created += 1,
                Err(error) => warn!(
                    file = %file_id,
                    error = %error,
                    "enrichment coverage pass could not persist facet"
                ),
            },
            Err(error) => warn!(
                file = %file_id,
                error = %error,
                "enrichment coverage pass could not enrich tracked body"
            ),
        }
    }

    if created > 0 || unreadable > 0 {
        info!(
            created,
            unreadable, "enrichment coverage pass created missing non-entity records"
        );
    }
    Ok(created)
}

/// Deferrals of one path before its log line escalates from debug to warn.
///
/// A file saved while the pass is reading it defers once and reconciles on the
/// retry. That is routine and must not write a warning on every editor save.
/// A path that keeps deferring is the livelock condition, so past this small
/// threshold the loop has to say so or it spends a core silently at info level.
const RETRY_WARN_ATTEMPTS: u32 = 3;

/// Ceiling of the per-path retry ladder, as a power-of-two multiple of the
/// loop's poll interval. Six doublings is 64 intervals, or 6.4s at the default
/// 100ms poll.
const RETRY_BACKOFF_MAX_SHIFT: u32 = 6;

/// Wait imposed on a path's `attempts`-th consecutive deferral.
///
/// The first retry waits one poll interval, which is the cadence at which the
/// loop already re-examines an idle working copy, so a path that merely lost one
/// race is retried no slower than a fresh notification would have been. Each
/// further consecutive deferral doubles the wait to a ceiling.
fn retry_backoff(attempts: u32, base: Duration) -> Duration {
    let shift = attempts.saturating_sub(1).min(RETRY_BACKOFF_MAX_SHIFT);
    base.saturating_mul(1u32 << shift)
}

/// What one deferral cost the path that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Deferral {
    /// Consecutive deferrals of this path, counting this one.
    attempts: u32,
    /// How long this path is held out of the loop before it is retried.
    wait: Duration,
}

#[derive(Debug, Clone, Copy)]
struct RetryLadder {
    attempts: u32,
    not_before: Instant,
}

/// Paths the reconcile pass deferred, with a per-path attempt ladder.
///
/// Every attempt at a path costs a complete exact-tree admission, so a path
/// rewritten faster than it reconciles cannot be re-injected on the next tick:
/// it would defer again, and the loop would spin at the speed of the storage
/// walk while admitting nothing. The ladder widens the wait for the offending
/// path alone, so an unstable path degrades into a slow lane while every other
/// path keeps its prompt first attempt. One tick that looks at a path without
/// deferring it forgets that path's ladder, which is what keeps a file that
/// settles from inheriting the wait it earned while it was flapping, and what
/// bounds the table to paths that are unstable right now.
#[derive(Debug, Default)]
struct RetryLane {
    /// Outstanding retries, in the order they were deferred.
    queued: VecDeque<PathBuf>,
    ladder: HashMap<PathBuf, RetryLadder>,
}

impl RetryLane {
    /// Defer `path` and widen its ladder by one step.
    fn defer(&mut self, path: &Path, now: Instant, base: Duration) -> Deferral {
        let ladder = self
            .ladder
            .entry(path.to_path_buf())
            .or_insert(RetryLadder {
                attempts: 0,
                not_before: now,
            });
        ladder.attempts = ladder.attempts.saturating_add(1);
        let wait = retry_backoff(ladder.attempts, base);
        ladder.not_before = now + wait;
        let deferral = Deferral {
            attempts: ladder.attempts,
            wait,
        };
        if !self.is_queued(path) {
            self.queued.push_back(path.to_path_buf());
        }
        deferral
    }

    /// Whether this path is waiting out a ladder step and must not be looked at.
    fn waiting(&self, path: &Path, now: Instant) -> bool {
        self.ladder
            .get(path)
            .is_some_and(|ladder| ladder.not_before > now)
    }

    /// Remove and return the outstanding retries whose ladder step has elapsed,
    /// in the order they were deferred. Their ladders are retained, so a path
    /// that defers again keeps climbing instead of restarting at one step.
    fn take_due(&mut self, now: Instant) -> Vec<PathBuf> {
        let mut due = Vec::new();
        let mut still_waiting = VecDeque::new();
        while let Some(path) = self.queued.pop_front() {
            if self.waiting(&path, now) {
                still_waiting.push_back(path);
            } else {
                due.push(path);
            }
        }
        self.queued = still_waiting;
        due
    }

    /// Forget a path's ladder and any outstanding retry for it.
    fn forget(&mut self, path: &Path) {
        self.ladder.remove(path);
        self.queued.retain(|queued| queued != path);
    }

    fn is_queued(&self, path: &Path) -> bool {
        self.queued.iter().any(|queued| queued == path)
    }

    /// Whether any retry is still owed. A ladder left behind for a path that has
    /// already been handed back to the loop is bookkeeping, not outstanding work.
    fn is_empty(&self) -> bool {
        self.queued.is_empty()
    }

    /// Whether any path is unstable right now, for the pass's deferred-work
    /// clock.
    ///
    /// Keyed on the ladder rather than the queue, and the difference decides
    /// whether the clock can measure a livelock at all. [`take_due`](Self::take_due)
    /// empties the queue every time a step elapses, so a queue-keyed clock would
    /// clear on each due tick and restart on the re-deferral, capping the
    /// reported age at one backoff step however long the loop churns. Ladders
    /// survive `take_due` and are dropped only by [`forget`](Self::forget), when
    /// a path actually settles, so this stays true across the whole spin.
    fn deferred_owed(&self) -> bool {
        !self.ladder.is_empty()
    }
}

/// Report one deferral of a path that changed while it was being reconciled.
///
/// This is the only one of the loop's deferral sites that is routine: an editor
/// save landing mid-read produces it once and the retry succeeds. It stayed at
/// debug for that reason, which is also why a path stuck in this state burned a
/// core for hours without writing a line at the daemon's info level. The first
/// occurrences stay at debug and a repeat escalates.
fn report_modified_during_reconcile(
    path: &Path,
    error: &kin_reconcile::ReconcileError,
    deferral: Deferral,
) {
    if deferral.attempts >= RETRY_WARN_ATTEMPTS {
        warn!(
            file = %path.display(),
            error = %error,
            attempts = deferral.attempts,
            backoff_ms = deferral.wait.as_millis(),
            "file keeps changing during reconcile; retrying it on a widening backoff"
        );
    } else {
        debug!(
            file = %path.display(),
            error = %error,
            attempts = deferral.attempts,
            "file changed during reconcile, queued for retry"
        );
    }
}

/// Whether a reconcile failure is the mid-read race that earns a retry.
///
/// Every other failure is reported and dropped: retrying it would repeat the
/// same complete admission for the same outcome.
fn reconcile_error_earns_retry(error: &kin_reconcile::ReconcileError) -> bool {
    matches!(
        error,
        kin_reconcile::ReconcileError::FileModifiedDuringReconcile { .. }
    )
}

/// Sweep expired coordination intents and record every automatic release
/// durably, under the same cross-surface gate used by registration and graph
/// apply.
///
/// Called once per reconcile tick, and kept alive by the parked loop after a
/// supervisor stop: intents are locks, and a daemon that keeps serving must
/// keep expiring them whether or not admission still runs.
async fn sweep_expired_intents(state: &DaemonState) {
    let _coordination = state.coordination_gate.lock().await;
    let mode = state.coordination_mode().as_str().to_string();
    match state
        .coordinator
        .sweep_expired_intents_with_reservation(|intent| {
            state
                .record_coordination_event(crate::state::CoordinationEventDraft {
                    event: "intent_release",
                    outcome: "pending:expired".to_string(),
                    session_id: Some(intent.session_id.to_string()),
                    intent_id: Some(intent.intent_id.to_string()),
                    intent_ids: vec![intent.intent_id.to_string()],
                    transaction_id: None,
                    scopes: intent.scopes.iter().map(crate::api::format_scope).collect(),
                    enforcement_mode: mode.clone(),
                    blocking_intent_ids: Vec::new(),
                })
                .map(|_| ())
        }) {
        Ok(reaped) => {
            for intent in &reaped {
                let _ = state.record_coordination_event(crate::state::CoordinationEventDraft {
                    event: "intent_release",
                    outcome: "expired".to_string(),
                    session_id: Some(intent.session_id.to_string()),
                    intent_id: Some(intent.intent_id.to_string()),
                    intent_ids: vec![intent.intent_id.to_string()],
                    transaction_id: None,
                    scopes: intent.scopes.iter().map(crate::api::format_scope).collect(),
                    enforcement_mode: mode.clone(),
                    blocking_intent_ids: Vec::new(),
                });
            }
            if !reaped.is_empty() {
                debug!(reaped = reaped.len(), "swept expired intents");
            }
        }
        Err(error) => {
            state.mark_coordination_evidence_incomplete(format!(
                "expired-intent sweep failed after reservation may have been written: {error}"
            ));
        }
    }
}

/// How many consecutive rounds the reconcile tick may stand down for commits
/// before it admits regardless.
///
/// A backstop rather than a hot path. A commit that is announcing itself is
/// either holding the coordination gate or queued on it, so a tick that
/// proceeds past this bound does not race that commit: it queues on the same
/// gate, and by the time it gets there the commit has admitted the whole
/// working copy and the tick finds nothing left to publish. What the bound
/// actually protects against is a client that keeps a commit handler inside the
/// daemon without ever reaching authority. The tick must not hold its own
/// admission for that forever, whatever else is wrong.
///
/// Eight rounds is under a second at the daemon's default cadence, and it is
/// several orders of magnitude longer than the gap between a commit announcing
/// itself and reaching the gate, which is the gap this yield exists to cover.
const MAX_CONSECUTIVE_COMMIT_YIELDS: u32 = 8;

/// The largest share of a publication that is worth spending to avoid one.
const COMMIT_YIELD_GRACE_SHARE: u32 = 8;

/// The largest number of poll intervals a tick will hold off for.
const COMMIT_YIELD_GRACE_INTERVALS: u32 = 5;

/// The upper bound on holding off, whatever the other two say.
const COMMIT_YIELD_GRACE_CEILING: Duration = Duration::from_secs(1);

/// How long a tick holds off before publishing, waiting to see whether a commit
/// is about to make its publication redundant.
///
/// The window matters because the two arrive together by construction: an agent
/// writes a file and runs `kin commit` in the same breath, the watcher
/// notification reaches this loop first, and the commit's own process is still
/// starting up. On the run this was measured against, the tick reached its
/// publication roughly 150ms before the commit reached the daemon, and then
/// spent 11.7 seconds publishing a tree the commit published again immediately
/// afterwards.
///
/// The wait is bounded three ways, because it is only ever worth a fraction of
/// what it saves. At most an eighth of what the last publication cost, so a
/// repository whose publications are microseconds waits microseconds and one
/// whose publications are seconds waits meaningfully. At most five poll
/// intervals, so a loop configured to react faster holds off proportionally
/// less. And never more than a second.
///
/// A daemon that has not published yet has no measurement to scale by, so it
/// uses the interval bound alone. That is the protective direction on purpose:
/// the first publication of a process is exactly the one whose cost is unknown.
fn commit_yield_grace(state: &DaemonState, interval: Duration) -> Duration {
    let ceiling = interval
        .saturating_mul(COMMIT_YIELD_GRACE_INTERVALS)
        .min(COMMIT_YIELD_GRACE_CEILING);
    match state.last_authority_publication() {
        Some(last) => (last / COMMIT_YIELD_GRACE_SHARE).min(ceiling),
        None => ceiling,
    }
}

/// Report whether this reconcile round should stand down for a commit.
///
/// True when one is already inside the daemon, when one has announced itself on
/// disk and has not arrived yet, or when one arrives while this waits out
/// [`commit_yield_grace`]. A commit admits the whole working copy itself and
/// carries the resulting tree in the transaction that publishes its change, so a
/// round that stands down loses no observation: its events stay queued, and the
/// next round either finds them already admitted or admits them itself.
///
/// The on-disk announcement is what makes the first round of a cold daemon
/// decidable. A commit that had to start this daemon reaches its handler only
/// after the store has opened, so on a large store the round and the request are
/// seconds apart and the round wins; widening the grace to cover that gap would
/// spend the widened window on every round that has no commit coming, which is
/// most of them. Reading an announcement the client already wrote costs nothing
/// when there is none.
///
/// The wait holds no lock. It happens before the round takes the coordination
/// gate, so the commit it is waiting for is never waiting on it.
async fn wait_out_imminent_commit(
    state: &DaemonState,
    interval: Duration,
    consecutive_yields: u32,
) -> bool {
    if consecutive_yields >= MAX_CONSECUTIVE_COMMIT_YIELDS {
        return false;
    }
    // Registered before the count is read, so a commit that announces itself in
    // between wakes this wait rather than falling between the two.
    let arrival = state.pending_commits.arrival();
    tokio::pin!(arrival);
    arrival.as_mut().enable();
    // A commit that had to start this daemon cannot have announced itself
    // inside it yet, so the on-disk announcement is read here too. This is the
    // point of the whole hold-off on a cold process: the client wrote its
    // announcement before it began waiting for the store to open, so it is
    // already readable on the first round of this daemon's life, and the round
    // stands down at once instead of waiting out a window sized against a
    // deadline nobody measured.
    state
        .pending_commits
        .refresh_approaching(state.layout.root());
    if state.pending_commits.any() {
        return true;
    }
    let grace = commit_yield_grace(state, interval);
    if grace.is_zero() {
        return false;
    }
    tokio::select! {
        _ = arrival => {}
        _ = tokio::time::sleep(grace) => {}
    }
    // Read again rather than assuming the wakeup was an arrival: a commit that
    // announced itself and finished inside the grace has already admitted this
    // working copy, and there is nothing left to stand down for.
    state
        .pending_commits
        .refresh_approaching(state.layout.root());
    state.pending_commits.any()
}

/// What the reconciliation loop becomes after the background-work supervisor
/// stops its pass: parked, not exited.
///
/// The loop's exit is one of the daemon's shutdown arms, so exiting on a
/// supervisor stop tore down the API task and every other task with it,
/// directly contradicting the stop announcement's "the daemon keeps serving"
/// (FIR-2317). Parking keeps the task alive doing only the coordination
/// housekeeping the daemon still owes, and ends on the daemon's own shutdown
/// signal. Admission stays stopped until a daemon restart clears the
/// in-memory halt, which is the "a restart retries it" the announcement
/// promises.
async fn park_reconcile_loop(
    state: &DaemonState,
    mut cancel: tokio::sync::watch::Receiver<bool>,
    interval: Duration,
) -> Result<()> {
    // A zero poll interval must not turn the parked loop into the very
    // CPU-spending spin the supervisor just stopped.
    let interval = interval.max(Duration::from_millis(200));
    loop {
        if *cancel.borrow() {
            state
                .reconciliation_status
                .store(RECON_IDLE, Ordering::Relaxed);
            info!("reconciliation loop shutting down");
            return Ok(());
        }
        sweep_expired_intents(state).await;
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.changed() => {}
        }
    }
}

/// Run the reconciliation loop until the cancellation token fires.
///
/// This is the main loop of the daemon. It:
/// 1. Watches the working directory for file changes (via `notify`)
/// 2. Drains batches of events
/// 3. For each event, runs the reconciler (file -> overlay)
/// 4. Projects overlay mutations back to files (overlay -> file)
///
/// The loop runs on a tokio task and shares state through `DaemonState`.
/// The reconcile loop's one-shot promise that its file watcher exists.
///
/// Fired on arming, and fired again on drop if the loop never got that far.
/// Drop-firing is the whole safety argument for making endpoint publication
/// wait on it. A loop can end before it ever builds a watcher — filesystem
/// reconcile switched off, a bare checkout, a watcher the host refused — and a
/// daemon that waited on a signal none of those paths sends would never publish
/// its endpoint at all, which is a worse failure than the unobserved window
/// this exists to close.
#[derive(Debug)]
pub struct WatchArmed(Option<tokio::sync::oneshot::Sender<()>>);

impl WatchArmed {
    pub fn new(signal: tokio::sync::oneshot::Sender<()>) -> Self {
        Self(Some(signal))
    }

    /// Report the watch, once. Later calls and the drop below do nothing.
    fn arm(&mut self) {
        if let Some(signal) = self.0.take() {
            let _ = signal.send(());
        }
    }
}

impl Drop for WatchArmed {
    fn drop(&mut self) {
        self.arm();
    }
}

/// When a startup catch-up should begin, or `None` when no window can be named.
///
/// The window opens at the last complete admission this store recorded, because
/// that is the last moment anything is known to have observed the working copy.
/// A file watcher only ever reports edits it was alive for, so everything the
/// host did between one daemon's last admission and the next daemon's watch was
/// seen by nobody, and nothing replays it. That stretch is the whole of the
/// "graph is one commit behind the work" complaint, and it is not only a
/// startup artifact: an idle timeout ends a daemon mid-session and the next
/// command starts a fresh one.
///
/// A store with no marker gets no catch-up. Absent means either never admitted
/// or admitted by a build older than the marker, and neither supplies a window;
/// with no lower bound the pass would propose the entire working copy, which is
/// exactly the sweep startup must not perform. An unreadable marker is the same
/// answer said louder, so it is logged rather than silently treated as absent.
fn startup_catch_up_window(state: &DaemonState) -> Option<SystemTime> {
    match kin_core::last_admission::read(&state.layout) {
        kin_core::last_admission::LastAdmissionRead::Recorded(recorded) => {
            let since = unix_instant(recorded.at);
            info!(
                since = %recorded.at.to_rfc3339(),
                "planning a startup catch-up over host paths modified since the last complete \
                 admission"
            );
            Some(since)
        }
        kin_core::last_admission::LastAdmissionRead::Absent => {
            debug!(
                "no last-admission marker, so no catch-up window can be named; working-copy \
                 divergence stays projection drift until an explicit seam admits it"
            );
            None
        }
        kin_core::last_admission::LastAdmissionRead::Unreadable(reason) => {
            warn!(
                reason = %reason,
                "the last-admission marker will not parse, so no catch-up window can be named; \
                 `kin admit` takes whatever the host changed while nothing was watching"
            );
            None
        }
    }
}

/// A UTC instant as a [`SystemTime`], for comparison against host modification
/// times.
///
/// A marker stamped before the epoch clamps to the epoch rather than wrapping.
/// No real store carries one, and a wrap would silently move the window to the
/// far future, which is the direction that loses every file.
fn unix_instant(at: chrono::DateTime<chrono::Utc>) -> SystemTime {
    let seconds = at.timestamp();
    if seconds < 0 {
        return SystemTime::UNIX_EPOCH;
    }
    SystemTime::UNIX_EPOCH + Duration::new(seconds as u64, at.timestamp_subsec_nanos())
}

/// Host events for every path the working copy changed at or after `since`.
///
/// Stat-only: the walk that produces this opens nothing and hashes nothing, so
/// a store whose host did not move since its last admission pays one traversal
/// and returns an empty list. The events it does return go through the ordinary
/// tick, so a catch-up path is admitted by the same bounded observation, the
/// same policy filter and the same compare-and-swap as one the watcher saw.
/// This plans no transition of its own and publishes nothing.
///
/// The bound is inclusive because filesystem modification times are coarse. A
/// file written in the same second the marker was stamped is re-observed, and
/// re-observing an unchanged path costs one admission that plans nothing.
fn plan_catch_up_events(state: &DaemonState, since: SystemTime) -> Result<Vec<FileEvent>> {
    let working_dir = state.layout.working_dir();
    let (_, policy) = current_authority_admission(state)?;
    let previous = state.graph.resolved_tree();
    let tracked_paths = previous
        .artifacts_by_path()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let graph_only_paths = crate::graph_only_members::members_of(&previous)?;
    let ignore =
        kin_index::RepositoryIgnore::load(working_dir).map_err(kin_index::IndexError::from)?;
    let modified = kin_index::scan_repository_modified_since(
        working_dir,
        &ignore,
        policy.as_ref(),
        tracked_paths.iter(),
        graph_only_paths.iter(),
        since,
    )
    .map_err(kin_index::IndexError::from)?;
    Ok(modified
        .iter()
        .filter_map(|path| kin_index::host_path_from_repo_path(working_dir, path).ok())
        .map(FileEvent::Changed)
        .collect())
}

/// Host events for every admitted source file the graph holds no entity for.
///
/// Entity derivation is not durable on its own. A tree admission publishes an
/// artifact into repository authority the moment the watcher sees the write,
/// while the entities the same tick derives live in this daemon's query graph
/// until a commit publishes them. A daemon that ends first, and an idle timeout
/// ends one after sixty seconds, takes them with it. What survives is a file
/// admitted at exactly the bytes on disk, so no later watcher event fires for
/// it and the startup catch-up window, which is keyed on host modification
/// time, cannot see it either: it was modified before the last admission, and
/// that admission is precisely what recorded the artifact. The path is then
/// permanently in the graph and permanently unqueryable, visible only as
/// `kin graph status` counting it among the files that "produced no entity".
///
/// This asks the graph rather than the host: an admitted path whose language
/// has a full adapter and which no entity names is either genuinely empty of
/// definitions, which costs one parse to re-confirm, or lost enrichment, which
/// this recovers. Every path goes back through the ordinary tick, so the same
/// bounded observation, policy filter and compare-and-swap apply as for an edit
/// a watcher saw.
fn plan_unenriched_source_events(state: &DaemonState) -> Result<Vec<FileEvent>> {
    use kin_model::EntityStore;

    let working_dir = state.layout.working_dir();
    let enriched: std::collections::HashSet<FilePathId> = state
        .graph
        .list_all_entities()?
        .into_iter()
        .filter_map(|entity| entity.file_origin)
        .collect();
    let mut events = Vec::new();
    for artifact in state.graph.resolved_tree().artifacts_by_path() {
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            != kin_core::SourceProjectionDisposition::Materialized
        {
            continue;
        }
        let Some(file_id) = semantic_file_id(&artifact.path) else {
            continue;
        };
        if enriched.contains(&file_id) {
            continue;
        }
        let Ok(host_path) = kin_index::host_path_from_repo_path(working_dir, &artifact.path) else {
            continue;
        };
        // Path-only classification, because the bytes are not read here. A file
        // whose extension carries no entity adapter is enriched by a shallow,
        // structured or opaque facet instead and is not owed a re-parse.
        if FileClassifier::classify(&host_path) != FileClassification::EntitySource {
            continue;
        }
        events.push(FileEvent::Changed(host_path));
    }
    Ok(events)
}

pub async fn run_loop(
    state: Arc<DaemonState>,
    config: LoopConfig,
    cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    run_loop_armed(state, config, cancel, None).await
}

/// Run the loop and report the moment its file watcher exists.
///
/// The daemon publishes `.kin/daemon.port` only after this fires, so a client
/// that finds the endpoint is finding a daemon that is already observing the
/// working copy. Before this signal existed the endpoint was published first
/// and the loop was spawned afterwards, so a write landing in between raised no
/// event and nothing ever replayed it: the graph simply never learned about
/// that file (FIR-2466).
pub async fn run_loop_armed(
    state: Arc<DaemonState>,
    config: LoopConfig,
    cancel: tokio::sync::watch::Receiver<bool>,
    armed: Option<WatchArmed>,
) -> Result<()> {
    // Held for the whole body so every early return below still releases the
    // daemon, through `WatchArmed`'s drop rather than through a call each of
    // those paths would have to remember.
    let mut armed = armed;
    if state.filesystem_reconcile_disabled() {
        info!(
            env = DISABLE_FILESYSTEM_RECONCILE_ENV,
            "filesystem watcher and reconciliation loop disabled; remote graph remains authoritative"
        );
        let mut cancel = cancel;
        while !*cancel.borrow() {
            if cancel.changed().await.is_err() {
                break;
            }
        }
        return Ok(());
    }

    let working_dir = state.layout.working_dir();
    if is_bare_repository(working_dir) {
        info!(working_dir = %working_dir.display(), "working directory is a bare Git repository; reconciliation loop disabled");
        let mut cancel = cancel;
        tokio::select! {
            _ = cancel.changed() => {}
        }
        return Ok(());
    }

    let watcher = FileWatcher::new(working_dir).map_err(DaemonError::from)?;
    // Read while the watcher is already reporting and before the endpoint can
    // be published, so the catch-up window and the watch meet rather than leave
    // a seam between them. Planning the pass itself is deliberately left to the
    // first round: the window is fixed here, the walk is not on the path to
    // publication, and a client finding the port is never waiting on a
    // traversal.
    let mut catch_up_owed = startup_catch_up_window(&state);
    // Owed once per daemon life, and independent of the catch-up window: the
    // paths it recovers are exactly the ones whose host modification time puts
    // them outside that window. A store with no last-admission marker gets no
    // catch-up and still gets this, because this bound comes from graph truth
    // rather than from a clock.
    let mut enrichment_repair_owed = true;
    if let Some(armed) = armed.as_mut() {
        armed.arm();
    }
    let enrichment_pipeline = IndexPipeline::new();
    // The watcher's running total of host events it could not place inside this
    // repository, as this loop last disclosed it. Held so a standing count is
    // reported once per rise rather than once per tick.
    let mut disclosed_events_outside_root = 0_u64;

    info!(
        poll_ms = config.poll_interval_ms,
        batch = config.batch_size,
        "reconciliation loop started"
    );

    // Startup sweeps nothing. Repository authority is already complete when the
    // daemon opens it, and the working copy is a derived view of that
    // authority. Admitting whatever bytes happen to sit on disk would publish
    // them into the repository-v6 workspace before any command runs, so a
    // command that spawned this daemon would observe ambiently ingested content
    // as graph-owned workspace state.
    //
    // The one exception is bounded by a clock rather than by taste. A file
    // watcher reports only the edits it was alive for, so the stretch between
    // one daemon's last complete admission and the next daemon's watch was
    // observed by nobody and nothing replays it. `catch_up_owed` above names
    // that stretch, and the first round below re-observes exactly the paths the
    // host modified inside it. Everything older is untouched: it predates the
    // last admission, which already covered it, and divergence with no window
    // to place it in stays projection drift until an explicit seam admits it.

    let interval = Duration::from_millis(config.poll_interval_ms);
    let mut cancel = cancel;
    // Track the effective batch size for backpressure catch-up.
    let base_batch_size = config.batch_size.max(1);
    if config.batch_size == 0 {
        warn!("reconciliation batch_size=0 is invalid; clamping to 1");
    }

    // RACE CONDITION HARDENING: Retry lane for files that were modified
    // during reconciliation. When a FileModifiedDuringReconcile error
    // occurs, the file watcher may have already drained the event for the
    // new content in the current batch. Without re-queuing, the file would
    // remain stale in the graph until the next external write. This lane
    // injects synthetic Changed events once a path's backoff has elapsed.
    let mut retry_lane = RetryLane::default();
    // Base of the per-path retry ladder. A zero poll interval would otherwise
    // make every ladder step zero, which is the spin the ladder exists to stop.
    let retry_base = interval.max(Duration::from_millis(1));

    // The watcher API drains its whole channel at once, while this loop deliberately
    // processes only a bounded batch per tick. Keep the unprocessed tail here so a burst
    // larger than `batch_size` is deferred instead of silently discarded.
    let mut pending_events: VecDeque<FileEvent> = VecDeque::new();
    let mut backlog_warning_active = false;
    // The admission policy the last complete pass planned against, kept so the
    // event filter below costs no authority load of its own. `None` until the
    // first pass resolves one, which is the safe direction: nothing is dropped
    // and the pass itself still enforces the policy exactly.
    let mut graph_owned_policy: Option<kin_index::ResolvedAdmissionMatcher> = None;
    // Rounds stood down in a row for commits, reset by every round that admits.
    // Bounded by MAX_CONSECUTIVE_COMMIT_YIELDS so a commit that never leaves the
    // daemon cannot hold ambient admission off forever.
    let mut commit_yields: u32 = 0;

    // Register with the self-limit supervisor. Registered here rather than at
    // daemon start so a repository that never runs this loop — filesystem
    // reconcile disabled, a bare checkout — reports no reconcile pass instead of
    // one that claims to be idle forever.
    let pass = state
        .background_work
        .pass(crate::background_work::PASS_RECONCILE);

    loop {
        // Check for shutdown signal.
        if *cancel.borrow() {
            state
                .reconciliation_status
                .store(RECON_IDLE, Ordering::Relaxed);
            pass.idle();
            // A loop that is gone owes nothing, whatever its ladder still held.
            pass.set_deferred(false, Instant::now());
            info!("reconciliation loop shutting down");
            break;
        }

        // The supervisor stopped this loop for spending the machine without
        // admitting anything. Enforced at this checkpoint, before any lock is
        // taken, so nothing is abandoned mid-transaction. Graph truth is
        // untouched and the daemon keeps serving it; what stops is the automatic
        // tracking of working-copy edits, which the announced reason says.
        //
        // Parking, not exiting, is what keeps that announcement true: this
        // loop's exit is a shutdown arm in the daemon's task supervision, so
        // returning here cancelled the API task and took the whole daemon down
        // twenty seconds after it promised to keep serving (FIR-2317). The
        // parked loop sheds the watcher and the admission machinery, keeps the
        // expired-intent sweep alive so coordination locks still expire, and
        // ends only on the daemon's own shutdown. The halt is in-memory state,
        // so a daemon restart retries the pass, exactly as announced.
        if pass.halted() {
            state
                .reconciliation_status
                .store(RECON_PARKED, Ordering::Relaxed);
            error!(
                reason = pass.halt_reason().unwrap_or_default(),
                "reconciliation loop stopped by the background-work supervisor; parking it while \
                 the daemon keeps serving (a daemon restart retries the pass)"
            );
            pass.idle();
            // A parked loop owes nothing, whatever its ladder still held.
            pass.set_deferred(false, Instant::now());
            // Shed the admission machinery: the watcher would keep buffering
            // events nothing will ever drain.
            drop(watcher);
            drop(pending_events);
            drop(retry_lane);
            return park_reconcile_loop(&state, cancel, interval).await;
        }

        sweep_expired_intents(&state).await;

        // The catch-up, owed once and taken on the first round that gets this
        // far. Enqueued as ordinary host events rather than admitted here, so
        // every one of them crosses authority through the same bounded
        // observation, the same policy filter and the same compare-and-swap a
        // watcher-observed edit does. A pass that fails is logged and dropped:
        // it is a repair, and retrying it forever would spend a traversal per
        // round on a store that already has an explicit seam for this.
        if let Some(since) = catch_up_owed.take() {
            match plan_catch_up_events(&state, since) {
                Ok(events) if events.is_empty() => {
                    debug!("no host path changed since the last complete admission");
                }
                Ok(events) => {
                    info!(
                        count = events.len(),
                        "admitting host paths modified since the last complete admission"
                    );
                    enqueue_file_events(&mut pending_events, events);
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        "could not plan the startup catch-up, so host content written while \
                         nothing was watching stays unadmitted until `kin admit` or a commit \
                         takes it"
                    );
                }
            }
        }

        // The enrichment repair, owed once for the same reason and taken the
        // same way. Loud when it finds anything: a file admitted with no
        // entities answered every query as an absence, and a store that has
        // been in that state deserves the count said out loud rather than
        // repaired in silence.
        if enrichment_repair_owed {
            enrichment_repair_owed = false;
            match plan_unenriched_source_events(&state) {
                Ok(events) if events.is_empty() => {
                    debug!("every admitted source path already carries its entities");
                }
                Ok(events) => {
                    warn!(
                        count = events.len(),
                        "admitted source paths carry no entities, so nothing can query them; \
                         re-deriving them now"
                    );
                    enqueue_file_events(&mut pending_events, events);
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        "could not plan the enrichment repair, so any admitted path missing its \
                         entities stays unqueryable until it is edited or committed"
                    );
                }
            }
        }

        // Collect retries first and real watcher notifications second. Dedup once per tick,
        // only when something new arrived; a real remove/recreate therefore supersedes a
        // synthetic Changed retry without repeatedly rebuilding an unchanged backlog.
        let tick_started = Instant::now();
        let mut incoming_events = Vec::new();
        let due_retries = retry_lane.take_due(tick_started);
        if !due_retries.is_empty() {
            debug!(
                count = due_retries.len(),
                "injecting retry events whose backoff elapsed"
            );
            incoming_events.extend(due_retries.into_iter().map(FileEvent::Changed));
        }
        incoming_events.extend(watcher.drain());
        // An event the watcher could not place inside this repository never
        // reaches anything below, so this loop is the only place that can say it
        // happened. Silence here is the whole defect: a repository reached
        // through a symlink took nothing from ambient admission and every
        // surface still reported a healthy daemon (FIR-2442). Reported through
        // the skipped-event probe, which is what turns a working daemon that is
        // seeing nothing into `attention` on `/health` and on `kin graph status`.
        let events_outside_root = watcher.events_outside_root();
        if let Some(disclosure) = events_outside_root_disclosure(
            &events_outside_root,
            disclosed_events_outside_root,
            working_dir,
        ) {
            disclosed_events_outside_root = events_outside_root.count;
            state
                .background_work
                .reconcile()
                .record_event_skipped(disclosure, tick_started);
        }
        // A graph-only repository member owns its own host subtree. Admission
        // already refuses to traverse one, so an event beneath it carries no
        // observation of this repository's source projection. Waking the tick
        // on such an event would still run a complete working-copy admission
        // and sweep unobserved host content into repository authority, so it
        // is dropped before it can schedule any work. Dropping it also ends any
        // ladder the path had, because a path that carries no observation of this
        // repository can never be retried and would otherwise leave an entry
        // behind that nothing clears.
        incoming_events.retain(|event| {
            if !event_is_beneath_graph_only_member(&state, event) {
                return true;
            }
            let (FileEvent::Changed(path) | FileEvent::Removed(path)) = event;
            retry_lane.forget(path);
            false
        });
        // A path the graph-owned admission policy excludes is dropped for the
        // same reason and with more force. Authority would refuse to admit it,
        // and that refusal is not per-path: it fails the whole exact-tree
        // admission, so one churning excluded file used to defer every other
        // path in the working copy and admit nothing (FIR-2346). Even with the
        // walk no longer proposing it, waking the tick on such an event would
        // still buy a complete working-copy admission that can only conclude
        // there is nothing to do, and a working stretch that records no
        // progress is what the supervisor eventually parks the loop for. So the
        // event never schedules work, and it ends whatever ladder the path had:
        // the rules exclude it, so no retry can ever reach a different answer.
        let mut policy_excluded_events = 0usize;
        incoming_events.retain(|event| {
            if !event_is_policy_excluded(&state, graph_owned_policy.as_ref(), event) {
                return true;
            }
            let (FileEvent::Changed(path) | FileEvent::Removed(path)) = event;
            retry_lane.forget(path);
            policy_excluded_events += 1;
            false
        });
        if policy_excluded_events > 0 {
            debug!(
                count = policy_excluded_events,
                "dropped host events for paths the graph-owned admission policy excludes"
            );
        }
        // A path already waiting out a ladder step is not looked at again until
        // that step elapses, whichever queue its next notification arrived on.
        // The retry is already owed and re-reads whatever the file then holds, so
        // dropping a repeat notification for it loses no observation while
        // sparing the complete exact-tree admission that observation would cost.
        // A removal is terminal rather than a flap: it is never held back, and it
        // ends the ladder because there is no longer a file to stabilize.
        incoming_events.retain(|event| match event {
            FileEvent::Removed(path) => {
                retry_lane.forget(path);
                true
            }
            FileEvent::Changed(path) => !retry_lane.waiting(path, tick_started),
        });
        enqueue_file_events(&mut pending_events, incoming_events);

        // Report the retry queue's own state every tick, including the ticks
        // that find nothing to do. This clock ages independently of the working
        // stretch below, which is what makes a ladder that never converges
        // visible: the loop keeps deferring the same paths, each individual tick
        // truthfully has nothing it may admit, and without this the pass reports
        // idle for the entire livelock.
        pass.set_deferred(retry_lane.deferred_owed(), tick_started);

        if pending_events.is_empty() {
            // Nothing to admit this tick, so the working stretch ends.
            //
            // This does NOT mean the loop is doing nothing. A tick that keeps
            // retrying the same unadmittable paths reaches here on every tick of
            // every ladder wait: the paths waiting out a step are dropped from
            // the incoming events above, and their retries are not yet due, so
            // the queue is empty while the work is still owed. That is why the
            // deferred clock above is a separate reading and why this state is
            // reported as `waiting_deferred` rather than `idle` whenever the
            // retry lane still holds something.
            pass.idle();
            // No events — sleep briefly then check again.
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.changed() => {
                    state.reconciliation_status.store(RECON_IDLE, Ordering::Relaxed);
                    pass.set_deferred(false, Instant::now());
                    info!("reconciliation loop shutting down");
                    break;
                }
            }
            continue;
        }

        // Stand this round down for a commit that is already inside the daemon,
        // or for one that announces itself while this waits. A commit forces a
        // complete admission of the working copy and carries the resulting tree
        // in the transaction that publishes its change, so a tick that publishes
        // first buys nothing and costs one whole O(store) publication. The
        // agent-shaped cadence, write a file and commit it immediately, puts
        // the watcher notification and the commit within a few hundred
        // milliseconds of each other, and the tick wins that race almost every
        // time.
        //
        // Nothing is lost by standing down: the events stay in the queue and no
        // path is deferred, because a yield is not a failure and must not feed
        // the retry ladder. The working stretch is deliberately not ended here
        // either. This path is bounded, and a stretch cleared on a path the loop
        // keeps reaching is a stretch the supervisor can no longer measure.
        if wait_out_imminent_commit(&state, interval, commit_yields).await {
            commit_yields += 1;
            debug!(
                consecutive = commit_yields,
                pending = pending_events.len(),
                "holding this reconcile round for a commit inside the daemon"
            );
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.changed() => {}
            }
            continue;
        }

        state
            .reconciliation_status
            .store(RECON_PROCESSING, Ordering::Relaxed);
        pass.working(Instant::now());

        // Backpressure stays bounded. A large burst remains in `pending_events` and is
        // consumed over multiple iterations; processing the entire queue under the write
        // locks would starve API tasks and delay cancellation.
        let event_count = pending_events.len();
        if event_count > base_batch_size.saturating_mul(4) {
            if !backlog_warning_active {
                warn!(
                    pending = event_count,
                    base_batch = base_batch_size,
                    "event queue backpressure — retaining bounded batches for fair catch-up"
                );
                backlog_warning_active = true;
            }
        } else {
            backlog_warning_active = false;
        }

        // Process only the configured prefix. `take_file_event_batch` removes that prefix
        // and leaves every later event in `pending_events` for the next loop iteration.
        let watcher_batch = take_file_event_batch(&mut pending_events, base_batch_size);
        debug!(
            count = watcher_batch.len(),
            "processing file events (after dedup)"
        );

        // Serialize exact-tree admission and semantic enrichment with every
        // other graph-authority mutation, including commit and checkout. The
        // clock guard below records mutation epochs; this mutex is the actual
        // exclusion boundary.
        let coordination = state.coordination_gate.lock().await;

        // Acquire the reconciler lock. Reconciliation derives one validated
        // TransactionDelta which is applied atomically to the live graph
        // staging view; there is no second mutable overlay authority.
        let mut reconciler = state.reconciler.write().await;
        let mut graph_changed = false;
        // Events this tick admitted without deferring them back to the retry
        // queue. This is the reconcile pass's persisted-progress counter: a tick
        // that re-observes the same paths and defers every one of them scores
        // zero however much work it did, which is the honest account of a loop
        // that is spending the machine and moving nothing.
        let mut admitted_events: u64 = 0;
        let mut projection_changed = ProjectionChangedSet::default();

        let mut lsp_changed: Vec<(kin_model::FilePathId, Vec<kin_model::EntityId>)> = Vec::new();
        let graph_mutation = state.begin_graph_authority_mutation();

        // One complete observation produces one exact tree transaction. This
        // coalesces remove/create watcher pairs (including pairs split across
        // notify batches) before either path can lose its ArtifactId. The
        // observed paths bound what the transaction may admit, so an ambient
        // tick publishes only host state it actually saw change.
        let observation = watcher_batch
            .iter()
            .filter_map(|event| match event {
                FileEvent::Changed(path) | FileEvent::Removed(path) => {
                    repo_path(path, state.layout.working_dir()).ok().flatten()
                }
            })
            .collect::<BTreeSet<_>>();
        let exact_admission = match exact_tree_admission(
            &state,
            Some(&observation),
            TreePublication::StandaloneUnlessACommitIsWaiting,
        ) {
            // A commit entered the daemon while this pass was walking the
            // working copy, so the pass derived a transition and published
            // nothing. Its events go back on the queue rather than into the
            // retry ladder: nothing failed, and the next round will find them
            // either already admitted by the commit or still owed.
            Ok(admission) if admission.yielded_to_pending_commit => {
                commit_yields += 1;
                drop(graph_mutation);
                drop(reconciler);
                drop(coordination);
                enqueue_file_events(&mut pending_events, watcher_batch);
                debug!(
                    consecutive = commit_yields,
                    "stood this reconcile round down at its publication for a commit inside \
                     the daemon"
                );
                state
                    .reconciliation_status
                    .store(RECON_IDLE, Ordering::Relaxed);
                tokio::time::sleep(interval).await;
                continue;
            }
            Ok(admission) => {
                commit_yields = 0;
                state
                    .background_work
                    .reconcile()
                    .record_admission_success(Instant::now());
                crate::background_work::record_durable_admission(
                    &state.layout,
                    state.graph.resolved_tree().len() as u64,
                );
                graph_owned_policy.clone_from(&admission.policy);
                admission
            }
            Err(error) => {
                warn!(
                    error = %error,
                    "complete exact-tree admission failed; retaining graph truth and retrying watcher paths"
                );
                let deferred_at = Instant::now();
                state
                    .background_work
                    .reconcile()
                    .record_admission_failure(&error, deferred_at);
                for event in &watcher_batch {
                    let (FileEvent::Changed(path) | FileEvent::Removed(path)) = event;
                    retry_lane.defer(path, deferred_at, retry_base);
                }
                drop(graph_mutation);
                drop(reconciler);
                drop(coordination);
                state
                    .reconciliation_status
                    .store(RECON_IDLE, Ordering::Relaxed);
                tokio::time::sleep(interval).await;
                continue;
            }
        };
        if !exact_admission.deltas.is_empty() {
            graph_changed = true;
            state.bump_version();
        }
        let mut batch = watcher_batch;
        batch.extend(exact_admission.semantic_events.iter().cloned());
        let batch = dedup_file_events(batch);

        for event in &batch {
            let admitted = match admit_file_event_with_exact_tree(
                &state,
                event,
                &exact_admission.changed_paths,
            ) {
                Ok(admitted) => admitted,
                Err(error) => {
                    warn!(error = %error, "failed to admit exact repository-tree entry");
                    state
                        .background_work
                        .reconcile()
                        .record_event_skipped(&error, Instant::now());
                    continue;
                }
            };
            if matches!(admitted, AdmittedFileEvent::Ignored) {
                continue;
            }
            if let AdmittedFileEvent::Untracked { repo_path } = &admitted {
                // Terminal for this tick, and deliberately not a deferral. The
                // complete scan that ran above already counted every untracked
                // path for the status surfaces, so this event has nothing left to
                // contribute and nothing to retry. Leaving it out of the ladder is
                // what lets the backlog drain and the loop go idle.
                debug!(
                    file = %repo_path,
                    "observed untracked host content; leaving it for an explicit admission seam"
                );
                continue;
            }

            let tree_changed = admitted.tree_changed();
            // Exact tree changes were admitted atomically for the whole batch
            // before optional semantic enrichment.
            if tree_changed && !matches!(&admitted, AdmittedFileEvent::Removed { .. }) {
                graph_changed = true;
            }
            let path = match event {
                FileEvent::Changed(path) | FileEvent::Removed(path) => path,
            };
            let admitted_repo_path = match &admitted {
                AdmittedFileEvent::Regular { repo_path, .. }
                | AdmittedFileEvent::Symlink { repo_path, .. }
                | AdmittedFileEvent::Removed { repo_path, .. } => repo_path,
                AdmittedFileEvent::Untracked { .. } | AdmittedFileEvent::Ignored => {
                    unreachable!()
                }
            };
            match host_entry_matches_graph(&state, path, admitted_repo_path) {
                Ok(true) => {}
                Ok(false) => {
                    let deferral = retry_lane.defer(path, Instant::now(), retry_base);
                    warn!(
                        file = %admitted_repo_path,
                        attempts = deferral.attempts,
                        backoff_ms = deferral.wait.as_millis(),
                        "host entry changed after exact-tree admission; deferring semantic enrichment"
                    );
                    if tree_changed {
                        state.bump_version();
                    }
                    continue;
                }
                Err(error) => {
                    let deferral = retry_lane.defer(path, Instant::now(), retry_base);
                    warn!(
                        file = %admitted_repo_path,
                        error = %error,
                        attempts = deferral.attempts,
                        backoff_ms = deferral.wait.as_millis(),
                        "could not revalidate exact host entry; deferring semantic enrichment"
                    );
                    if tree_changed {
                        state.bump_version();
                    }
                    continue;
                }
            }
            admitted_events += 1;

            let (semantic_event, semantic_repo_path) = match admitted {
                AdmittedFileEvent::Regular {
                    repo_path,
                    file_id,
                    content,
                    blob_hash,
                    entry,
                    ..
                } => {
                    let Some(file_id) = file_id else {
                        debug!(
                            file = %repo_path,
                            ?entry,
                            "admitted byte-exact non-UTF-8 path without UTF-8 semantic enrichment"
                        );
                        if tree_changed {
                            state.bump_version();
                        }
                        continue;
                    };
                    let classification = FileClassifier::classify_with_content(path, &content);
                    if classification != FileClassification::EntitySource {
                        match enrichment_pipeline.index_any_content(&file_id, &content, blob_hash) {
                            Ok(indexed) => match persist_non_entity_enrichment(&state, indexed) {
                                Ok((file_id, cleanup)) => {
                                    projection_changed.remove(file_id.clone());
                                    for id in cleanup.removed_entities {
                                        state.emit_event(DaemonEvent::EntityChanged {
                                            entity_id: id,
                                            change_type: ChangeType::Deleted,
                                            file_path: Some(file_id.0.clone()),
                                            session_id: None,
                                        });
                                    }
                                    graph_changed = true;
                                    state.bump_version();
                                }
                                Err(error) => {
                                    warn!(
                                        file = %file_id,
                                        error = %error,
                                        "tree entry admitted but enrichment facet persistence failed"
                                    );
                                    if tree_changed {
                                        state.bump_version();
                                    }
                                }
                            },
                            Err(error) => {
                                warn!(
                                    file = %file_id,
                                    error = %error,
                                    "tree entry admitted but optional enrichment failed"
                                );
                                if tree_changed {
                                    state.bump_version();
                                }
                            }
                        }
                        continue;
                    }

                    match clear_incompatible_facets(&state, &file_id, EnrichmentFacet::EntitySource)
                    {
                        Ok(cleanup) => {
                            graph_changed |= cleanup.changed;
                        }
                        Err(error) => {
                            warn!(
                                file = %file_id,
                                error = %error,
                                "tree entry admitted but incompatible facet cleanup failed"
                            );
                        }
                    }
                    (FileEvent::Changed(path.clone()), repo_path)
                }
                AdmittedFileEvent::Symlink {
                    repo_path,
                    file_id,
                    entry,
                    ..
                } => {
                    let Some(file_id) = file_id else {
                        debug!(
                            file = %repo_path,
                            ?entry,
                            "admitted byte-exact non-UTF-8 symlink without UTF-8 enrichment"
                        );
                        if tree_changed {
                            state.bump_version();
                        }
                        continue;
                    };
                    match clear_incompatible_facets(&state, &file_id, EnrichmentFacet::None) {
                        Ok(cleanup) => {
                            for id in cleanup.removed_entities {
                                state.emit_event(DaemonEvent::EntityChanged {
                                    entity_id: id,
                                    change_type: ChangeType::Deleted,
                                    file_path: Some(file_id.0.clone()),
                                    session_id: None,
                                });
                            }
                            projection_changed.remove(file_id.clone());
                            graph_changed |= cleanup.changed;
                            if tree_changed || cleanup.changed {
                                state.bump_version();
                            }
                            debug!(
                                file = %file_id,
                                ?entry,
                                "admitted symlink tree entry without source enrichment"
                            );
                        }
                        Err(error) => {
                            warn!(
                                file = %file_id,
                                error = %error,
                                "symlink tree entry admitted but facet cleanup failed"
                            );
                            if tree_changed {
                                state.bump_version();
                            }
                        }
                    }
                    continue;
                }
                AdmittedFileEvent::Removed {
                    repo_path, file_id, ..
                } => {
                    if !tree_changed {
                        continue;
                    }
                    match finalize_tree_removal(&state, file_id.as_ref(), tree_changed) {
                        Ok(cleanup) => {
                            if let Some(file_id) = &file_id {
                                projection_changed.remove(file_id.clone());
                                for id in cleanup.removed_entities {
                                    state.emit_event(DaemonEvent::EntityChanged {
                                        entity_id: id,
                                        change_type: ChangeType::Deleted,
                                        file_path: Some(file_id.0.clone()),
                                        session_id: None,
                                    });
                                }
                            }
                            graph_changed = true;
                            state.bump_version();
                            debug!(file = %repo_path, "removed exact repository-tree entry");
                        }
                        Err(error) => warn!(
                            file = %repo_path,
                            error = %error,
                            "failed to remove repository entry atomically; retaining tree truth"
                        ),
                    }
                    continue;
                }
                AdmittedFileEvent::Untracked { .. } | AdmittedFileEvent::Ignored => {
                    unreachable!()
                }
            };

            match reconciler.reconcile_file_change(
                &semantic_event,
                &state.blobs,
                state.graph.as_ref(),
            ) {
                Ok(result) => {
                    let (outcome, delta) = result.into_parts();
                    debug!(?outcome, "reconcile outcome");

                    use kin_reconcile::ReconcileOutcome;
                    let should_apply = matches!(
                        &outcome,
                        ReconcileOutcome::Updated { .. } | ReconcileOutcome::FileRemoved { .. }
                    );
                    if should_apply {
                        match host_entry_matches_graph(&state, path, &semantic_repo_path) {
                            Ok(true) => {}
                            Ok(false) => {
                                let deferral = retry_lane.defer(path, Instant::now(), retry_base);
                                warn!(
                                    file = %semantic_repo_path,
                                    attempts = deferral.attempts,
                                    backoff_ms = deferral.wait.as_millis(),
                                    "host entry changed during semantic reconciliation; discarded transaction and queued retry"
                                );
                                if tree_changed {
                                    state.bump_version();
                                }
                                continue;
                            }
                            Err(error) => {
                                let deferral = retry_lane.defer(path, Instant::now(), retry_base);
                                warn!(
                                    file = %semantic_repo_path,
                                    error = %error,
                                    attempts = deferral.attempts,
                                    backoff_ms = deferral.wait.as_millis(),
                                    "could not revalidate reconciled host entry; discarded transaction and queued retry"
                                );
                                if tree_changed {
                                    state.bump_version();
                                }
                                continue;
                            }
                        }
                        if let Err(e) = state.graph.apply_transaction_delta(&delta) {
                            warn!(error = %e, "failed to apply reconciled transaction into primary graph");
                            if tree_changed {
                                state.bump_version();
                            }
                            continue;
                        }
                        if let Err(e) =
                            state.persist_projection_truth_from_reconcile(&reconciler, &outcome)
                        {
                            warn!(error = %e, "failed to persist projection truth after reconcile");
                        }
                        projection_changed.record_reconcile_outcome(&outcome);
                        graph_changed = true;
                    }

                    if let ReconcileOutcome::Updated {
                        file_id,
                        added,
                        modified,
                        removed,
                        ..
                    } = &outcome
                    {
                        let file_path = path.to_string_lossy().to_string();
                        for id in added {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Created,
                                file_path: Some(file_path.clone()),
                                // FS-reconcile loop: a raw filesystem change has
                                // no owning agent, so attribution is honestly None.
                                session_id: None,
                            });
                        }
                        for id in modified {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Modified,
                                file_path: Some(file_path.clone()),
                                // FS-reconcile loop: a raw filesystem change has
                                // no owning agent, so attribution is honestly None.
                                session_id: None,
                            });
                        }
                        for id in removed {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Deleted,
                                file_path: Some(file_path.clone()),
                                // FS-reconcile loop: a raw filesystem change has
                                // no owning agent, so attribution is honestly None.
                                session_id: None,
                            });
                        }
                        if should_apply || tree_changed {
                            state.bump_version();
                        }

                        // Collect entity IDs for LSP enrichment.
                        let mut changed_ids: Vec<kin_model::EntityId> = Vec::new();
                        changed_ids.extend(added.iter().copied());
                        changed_ids.extend(modified.iter().copied());
                        debug!(
                            added = added.len(),
                            modified = modified.len(),
                            removed = removed.len(),
                            total_for_lsp = changed_ids.len(),
                            "reconcile entity counts for LSP enrichment"
                        );
                        if !changed_ids.is_empty() {
                            lsp_changed.push((file_id.clone(), changed_ids));
                        }
                    } else if let ReconcileOutcome::FileRemoved {
                        removed, file_id, ..
                    } = &outcome
                    {
                        let file_path = path.to_string_lossy().to_string();
                        for id in removed {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Deleted,
                                file_path: Some(file_path.clone()),
                                // FS-reconcile loop: a raw filesystem change has
                                // no owning agent, so attribution is honestly None.
                                session_id: None,
                            });
                        }
                        match clear_incompatible_facets(&state, file_id, EnrichmentFacet::None) {
                            Ok(_) => {
                                projection_changed.remove(file_id.clone());
                            }
                            Err(error) => {
                                warn!(
                                    file = %file_id,
                                    error = %error,
                                    "removed tree entry but failed to clear every enrichment facet"
                                );
                            }
                        }

                        if should_apply || tree_changed {
                            state.bump_version();
                        }
                    } else if tree_changed {
                        // Broken-AST/LKG outcomes still publish the exact bytes
                        // and mode admitted before parser enrichment.
                        state.bump_version();
                    }
                }
                Err(e) => {
                    // FileModifiedDuringReconcile is an expected race — the file
                    // changed while we were processing it. Re-queue the file so
                    // it's reconciled on a later tick even if the watcher already
                    // drained the event for the new content in this batch.
                    if reconcile_error_earns_retry(&e) {
                        let deferral = retry_lane.defer(path, Instant::now(), retry_base);
                        report_modified_during_reconcile(path, &e, deferral);
                    } else {
                        // Retrying a deterministic failure would re-derive the
                        // same rejected transaction forever, so the event is
                        // dropped. Name the path: its enrichment now stays at
                        // whatever the last accepted pass admitted, and an
                        // error without a path cannot be traced back to it.
                        warn!(
                            file = %semantic_repo_path,
                            error = %e,
                            "reconciliation error for event; dropping it and leaving this path's enrichment stale"
                        );
                        state.background_work.reconcile().record_event_skipped(
                            format!("{semantic_repo_path}: {e}"),
                            Instant::now(),
                        );
                    }
                    if tree_changed {
                        state.bump_version();
                    }
                }
            }
        }
        drop(graph_mutation);

        // Every path this tick looked at without deferring is stable as far as
        // the pass can tell, so its ladder is forgotten and its next deferral
        // starts at one interval again. This covers admission, ignored paths, and
        // enrichment failures alike, and it is what bounds the ladder table to
        // the paths that are unstable right now.
        for event in &batch {
            let (FileEvent::Changed(path) | FileEvent::Removed(path)) = event;
            if !retry_lane.is_queued(path) {
                retry_lane.forget(path);
            }
        }

        // Drop write locks before rebuilding projection (it takes its own locks).
        drop(reconciler);
        drop(coordination);

        // Queue only changed entities for LSP enrichment.
        for (file_id, entity_ids) in lsp_changed {
            state.queue_lsp_enrichment(LspEnrichmentRequest {
                file_id,
                changed_entity_ids: entity_ids,
            });
        }

        // Refresh projection cache so VFS reads serve fresh content.
        // Persistence is handled by the background save task — the reconcile
        // loop just marks the graph dirty and refreshes touched projection rows.
        if graph_changed {
            state.mark_dirty();
            let projection_result = if projection_changed.is_empty() {
                state.rebuild_projection().await
            } else {
                state.refresh_projection(&projection_changed).await
            };
            if let Err(e) = projection_result {
                error!(error = %e, "failed to refresh projection after reconciliation");
            }
        }

        pass.advanced(admitted_events, Instant::now());

        let backlog_remains = !pending_events.is_empty() || !retry_lane.is_empty();
        // Reported from the loop's own predicate rather than recomputed on the
        // status surface, which cannot see either queue. A backlog that never
        // clears is how a wedged retry ladder looks from outside: the loop is
        // busy, its status alternates, and nothing is being admitted.
        state
            .background_work
            .reconcile()
            .observe_backlog(backlog_remains, Instant::now());
        if !backlog_remains {
            state
                .reconciliation_status
                .store(RECON_IDLE, Ordering::Relaxed);
        }

        // Mark initialized after the first successful reconciliation cycle.
        if !state.is_initialized.load(Ordering::Relaxed) {
            state.is_initialized.store(true, Ordering::Relaxed);
            info!("daemon initialized after first reconciliation cycle");
        }

        // A retained backlog should catch up promptly, but yield between batches so the
        // daemon's other Tokio tasks and the cancellation sender are never starved.
        //
        // Only work this loop can pick up without waiting earns the yield. When the
        // only backlog left is a retry lane serving out its ladder, yielding would
        // return immediately into another complete exact-tree admission for a path
        // that is not eligible yet, which is the spin that burned a core for hours.
        // That case waits the poll interval instead: the same cadence the loop uses
        // when it has nothing to do, short enough that a fresh notification for any
        // other path is still picked up promptly, and interruptible so shutdown does
        // not wait on it.
        if !pending_events.is_empty() {
            tokio::task::yield_now().await;
        } else if !retry_lane.is_empty() {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.changed() => {}
            }
        }
    }

    Ok(())
}

/// Deduplicate file events, keeping only the last event per path.
///
/// When multiple events arrive for the same file in a single batch (e.g.,
/// rapid saves, multi-file refactors), only the last event matters because
/// the reconciler will read the file at its current state. A `Removed` event
/// supersedes any prior `Changed` events, and a `Changed` event after a
/// `Removed` means the file was recreated.
///
/// Preserves the relative order of the last event per unique path.
fn dedup_file_events(events: Vec<FileEvent>) -> Vec<FileEvent> {
    // Track the last event per path, preserving insertion order via index.
    let mut last_event: HashMap<PathBuf, (usize, FileEvent)> = HashMap::new();
    for (idx, event) in events.into_iter().enumerate() {
        let path = match &event {
            FileEvent::Changed(p) | FileEvent::Removed(p) => p.clone(),
        };
        last_event.insert(path, (idx, event));
    }

    // Sort by original index to preserve temporal order.
    let mut deduped: Vec<(usize, FileEvent)> = last_event.into_values().collect();
    deduped.sort_by_key(|(idx, _)| *idx);
    deduped.into_iter().map(|(_, event)| event).collect()
}

/// Append events to the retained watcher backlog and keep only the last event per path.
///
/// Deduplicating the whole backlog, rather than just the next processing batch, also handles a
/// path whose superseding event arrives after an earlier event was deferred to the next tick.
fn enqueue_file_events(
    pending: &mut VecDeque<FileEvent>,
    events: impl IntoIterator<Item = FileEvent>,
) {
    let incoming = events.into_iter().collect::<Vec<_>>();
    if incoming.is_empty() {
        return;
    }

    let mut combined = Vec::with_capacity(pending.len() + incoming.len());
    combined.extend(pending.drain(..));
    combined.extend(incoming);
    pending.extend(dedup_file_events(combined));
}

/// Remove at most `batch_size` events from the front of the retained backlog.
fn take_file_event_batch(pending: &mut VecDeque<FileEvent>, batch_size: usize) -> Vec<FileEvent> {
    let count = batch_size.max(1).min(pending.len());
    (0..count).filter_map(|_| pending.pop_front()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn open_test_state(repo: &tempfile::TempDir) -> Arc<DaemonState> {
        let init = kin_core::init(repo.path()).unwrap();
        Arc::new(DaemonState::open(init.layout).unwrap())
    }

    /// FIR-2442. A dropped host event is disclosed through the reconcile health
    /// surface, naming the root it could not be placed in and the path itself.
    #[test]
    fn an_event_outside_the_bound_root_is_disclosed_with_both_paths() {
        let events = kin_index::EventsOutsideRoot {
            count: 2,
            last_path: Some(PathBuf::from("/private/var/repo/main.rs")),
        };

        let disclosure = events_outside_root_disclosure(&events, 0, Path::new("/var/repo"))
            .expect("a risen count is disclosed");

        assert!(
            disclosure.contains("/var/repo"),
            "the disclosure names the bound root: {disclosure}"
        );
        assert!(
            disclosure.contains("/private/var/repo/main.rs"),
            "the disclosure names the dropped path: {disclosure}"
        );
        assert!(
            disclosure.contains('2'),
            "the disclosure carries the count: {disclosure}"
        );
    }

    /// The same standing count is stated once. A running total re-read every
    /// tick would otherwise re-record one unchanged fault forever.
    #[test]
    fn an_already_disclosed_outside_root_count_is_not_restated() {
        let events = kin_index::EventsOutsideRoot {
            count: 2,
            last_path: Some(PathBuf::from("/private/var/repo/main.rs")),
        };

        assert_eq!(
            events_outside_root_disclosure(&events, 2, Path::new("/var/repo")),
            None,
            "a count that has not risen is not new evidence"
        );
        assert!(
            events_outside_root_disclosure(&events, 1, Path::new("/var/repo")).is_some(),
            "a count that rose by one is"
        );
    }

    /// FIR-2442. What the disclosure is for: the reconcile surface stops
    /// reporting a healthy loop once a host event has been dropped unplaced.
    #[test]
    fn a_disclosed_outside_root_event_degrades_the_reconcile_surface() {
        let probes = crate::background_work::ReconcileProbes::default();
        let now = Instant::now();
        assert!(
            !probes.report(now).degraded(),
            "a loop that has dropped nothing is not degraded"
        );

        let events = kin_index::EventsOutsideRoot {
            count: 1,
            last_path: Some(PathBuf::from("/private/var/repo/main.rs")),
        };
        let disclosure = events_outside_root_disclosure(&events, 0, Path::new("/var/repo"))
            .expect("a risen count is disclosed");
        probes.record_event_skipped(disclosure, now);

        let report = probes.report(now);
        assert!(report.degraded(), "a dropped host event is a degraded loop");
        let reasons = report.degraded_reasons().join(" ");
        assert!(
            reasons.contains("/private/var/repo/main.rs"),
            "the degraded reason names the dropped path: {reasons}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repo_path_accepts_a_host_alias_without_dereferencing_the_leaf() {
        use std::os::unix::fs::symlink;

        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let aliases = tempfile::tempdir().unwrap();
        let alias = aliases.path().join("repo-alias");
        symlink(repo.path(), &alias).unwrap();
        symlink("missing-target", repo.path().join("current")).unwrap();

        assert_eq!(
            repo_path(&alias.join("current"), state.layout.working_dir()).unwrap(),
            Some(test_repo_path("current")),
            "host-root aliases must normalize while a dangling symlink remains the repository entry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repo_path_rejects_a_directory_symlink_escape() {
        use std::os::unix::fs::symlink;

        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), repo.path().join("escape")).unwrap();

        // Build the event from the canonical root so the path is already a
        // lexical child of the repository. Containment must then be decided by
        // resolving the parent, not by the string prefix alone.
        let root = state.layout.working_dir().to_path_buf();
        let error = repo_path(&root.join("escape/secret.txt"), &root)
            .expect_err("a lexical child that resolves outside the repository must be rejected");
        assert!(error.to_string().contains("escaped repository root"));
    }

    #[test]
    fn repo_path_keeps_identity_for_an_entry_whose_parent_is_already_gone() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let root = state.layout.working_dir().to_path_buf();
        std::fs::create_dir_all(root.join("removed")).unwrap();
        std::fs::write(root.join("removed/module.rs"), b"fn gone() {}\n").unwrap();
        std::fs::remove_dir_all(root.join("removed")).unwrap();

        // Removal events arrive after the directory is gone. Resolving the
        // nearest existing ancestor keeps the entry admissible instead of
        // dropping its removal on a missing-parent error.
        assert_eq!(
            repo_path(&root.join("removed/module.rs"), &root).unwrap(),
            Some(test_repo_path("removed/module.rs"))
        );
    }

    fn test_repo_path(path: &str) -> RepoPath {
        RepoPath::from_utf8(path).unwrap()
    }

    fn tree_entry(state: &DaemonState, path: &str) -> Option<TreeEntry> {
        state
            .graph
            .resolved_tree()
            .artifact_at_path(&test_repo_path(path))
            .map(|artifact| artifact.entry)
    }

    fn read_tree_entry_bytes(state: &DaemonState, entry: TreeEntry) -> Vec<u8> {
        let hash = entry
            .blob_identity()
            .expect("fixture tree entry must carry local blob bytes");
        state.blobs.read(&kin_blobs::Hash256(hash.0)).unwrap()
    }

    fn authority_tree(state: &DaemonState) -> kin_model::ResolvedTree {
        let manifest =
            kin_core::manifest::KinManifest::load(&state.layout.manifest_path()).unwrap();
        let repository_id = kin_model::RepositoryId::new(manifest.repo_id).unwrap();
        let workspace_id = kin_model::WorkspaceId::from_uuid(
            uuid::Uuid::parse_str(&manifest.workspace_id).unwrap(),
        );
        let authority = kin_db::RepositoryAuthorityManager::open(
            repository_id,
            Arc::new(kin_db::LocalFileBackend::new(state.layout.kindb_dir())),
        )
        .unwrap();
        authority
            .read_authority()
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .unwrap()
            .tree
            .clone()
    }

    #[test]
    fn graph_only_flag_accepts_only_explicit_truthy_values() {
        for value in ["1", "true", " TRUE ", "yes", "on", "ON"] {
            assert!(env_flag_enabled(Some(value.to_string())), "{value}");
        }
        for value in ["", "0", "false", "off", "no", "graph-only"] {
            assert!(!env_flag_enabled(Some(value.to_string())), "{value}");
        }
        assert!(!env_flag_enabled(None));
    }

    #[test]
    fn storage_backend_graph_authority_cannot_be_reenabled_by_environment() {
        assert!(!resolve_filesystem_reconcile_disabled(false, false));
        assert!(resolve_filesystem_reconcile_disabled(false, true));
        assert!(resolve_filesystem_reconcile_disabled(true, false));
        assert!(resolve_filesystem_reconcile_disabled(true, true));
    }

    #[tokio::test]
    async fn graph_only_mode_skips_direct_sync_and_run_loop_without_mass_delete_override() {
        let mass_delete_before = std::env::var_os("KIN_ALLOW_MASS_DELETION");

        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/lib.rs"), "pub fn disk_only() {}\n").unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let state = Arc::new(DaemonState::open(init.layout).unwrap());
        state
            .filesystem_reconcile_disabled
            .store(true, std::sync::atomic::Ordering::Relaxed);

        sync_filesystem_with_graph(&state).await.unwrap();
        assert_eq!(state.graph.entity_count(), 0, "direct sync must be inert");

        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(true);
        run_loop(Arc::clone(&state), LoopConfig::default(), cancel_rx)
            .await
            .unwrap();
        assert_eq!(state.graph.entity_count(), 0, "run loop must be inert");
        assert!(!state.is_mass_deletion_blocked());
        assert_eq!(
            std::env::var_os("KIN_ALLOW_MASS_DELETION"),
            mass_delete_before,
            "graph-only mode must not set or clear the mass-deletion escape hatch"
        );
    }

    /// FIR-2317: a background-work supervisor stop parks the reconciliation
    /// loop; it must not exit the loop task. In the daemon, the loop task's
    /// exit is a shutdown arm that cancels the API task and drains everything,
    /// so an exit here is exactly the "stopped a stalled pass, lost the whole
    /// daemon" failure, twenty seconds after announcing "the daemon keeps
    /// serving".
    #[tokio::test]
    async fn a_supervisor_stop_parks_the_loop_instead_of_exiting_it() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        // The supervisor's verdict, delivered before the loop starts so its
        // first checkpoint observes it.
        state
            .background_work
            .pass(crate::background_work::PASS_RECONCILE)
            .halt("test: the reconcile pass was stopped by the supervisor");

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let mut handle = tokio::spawn(run_loop(
            Arc::clone(&state),
            LoopConfig::default(),
            cancel_rx,
        ));

        // Wait for the loop to reach its checkpoint and park. The parked
        // status is the observable that separates "parked" from "not yet
        // scheduled", so this poll cannot pass vacuously on a slow machine.
        let deadline = Instant::now() + Duration::from_secs(30);
        while state.reconciliation_status.load(Ordering::Relaxed) != RECON_PARKED {
            assert!(
                !handle.is_finished(),
                "the reconciliation loop exited on a supervisor stop; in the daemon this \
                 cancels the API task and takes the whole daemon down (FIR-2317)"
            );
            assert!(
                Instant::now() < deadline,
                "the loop never reached its supervisor-stop checkpoint"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            state.reconciliation_status_str(),
            "parked-by-supervisor",
            "status surfaces must report the stop, not describe the loop as idle"
        );

        // Parked is not exited: the task must still be alive after the
        // checkpoint has provably run.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !handle.is_finished(),
            "the parked loop must stay alive until the daemon itself shuts down"
        );

        // The daemon's own shutdown still ends the parked loop cleanly.
        cancel_tx.send(true).unwrap();
        let joined = tokio::time::timeout(Duration::from_secs(30), &mut handle)
            .await
            .expect("a parked reconciliation loop must still exit on shutdown")
            .expect("the parked loop task must not panic");
        joined.expect("the parked loop must exit cleanly");
        assert_eq!(
            state.reconciliation_status.load(Ordering::Relaxed),
            RECON_IDLE,
            "shutdown returns the status to idle"
        );

        // The halt is in-memory supervisor state, which is what makes the
        // announcement's "a restart retries it" true: a fresh daemon process
        // starts with an unhalted pass.
        drop(handle);
        drop(state);
        let reopened = kin_core::KinLayout::discover(repo.path())
            .expect("the repository layout must still be discoverable");
        let restarted = DaemonState::open(reopened).expect("a fresh daemon state must open");
        assert!(
            !restarted
                .background_work
                .pass(crate::background_work::PASS_RECONCILE)
                .halted(),
            "a restarted daemon must retry the reconcile pass"
        );
    }

    #[cfg(unix)]
    #[test]
    fn admission_preserves_unsupported_bytes_and_executable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let path = repo.path().join("tool.custom");
        let content = b"#!/opt/custom/runtime\nrun something\n";
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let admitted = admit_file_event(&state, &FileEvent::Changed(path.clone())).unwrap();
        let AdmittedFileEvent::Regular {
            file_id,
            entry,
            tree_changed,
            ..
        } = admitted
        else {
            panic!("unsupported regular file must be admitted");
        };
        assert!(tree_changed);
        assert_eq!(file_id, Some(FilePathId::new("tool.custom")));
        assert!(matches!(
            entry,
            TreeEntry::Blob {
                executable: true,
                ..
            }
        ));
        assert_eq!(read_tree_entry_bytes(&state, entry), content);
        assert_eq!(tree_entry(&state, "tool.custom"), Some(entry));
        assert_eq!(
            authority_tree(&state)
                .artifact_at_path(&test_repo_path("tool.custom"))
                .unwrap()
                .entry,
            entry,
            "unsupported executable must cross repository authority before graph admission"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let admitted = admit_file_event(&state, &FileEvent::Changed(path)).unwrap();
        let AdmittedFileEvent::Regular { entry, .. } = admitted else {
            panic!("mode-only edit must remain a regular tree entry");
        };
        assert!(matches!(
            entry,
            TreeEntry::Blob {
                executable: false,
                ..
            }
        ));
        assert_eq!(read_tree_entry_bytes(&state, entry), content);
        assert_eq!(
            authority_tree(&state)
                .artifact_at_path(&test_repo_path("tool.custom"))
                .unwrap()
                .entry,
            entry,
            "mode-only edits must remain exact repository authority"
        );
    }

    #[test]
    fn semantic_revalidation_detects_bytes_changed_after_tree_admission() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let path = repo.path().join("src.rs");
        let repo_path = test_repo_path("src.rs");
        std::fs::write(&path, b"fn admitted() {}\n").unwrap();

        admit_file_event(&state, &FileEvent::Changed(path.clone())).unwrap();
        assert!(host_entry_matches_graph(&state, &path, &repo_path).unwrap());

        std::fs::write(&path, b"fn changed_after_admission() {}\n").unwrap();
        assert!(!host_entry_matches_graph(&state, &path, &repo_path).unwrap());
        let entry = tree_entry(&state, "src.rs").unwrap();
        assert_eq!(read_tree_entry_bytes(&state, entry), b"fn admitted() {}\n");
    }

    #[cfg(unix)]
    #[test]
    fn admission_preserves_dangling_symlink_target_bytes() {
        use std::os::unix::fs::symlink;

        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let path = repo.path().join("current");
        symlink("../releases/not-present", &path).unwrap();

        let admitted = admit_file_event(&state, &FileEvent::Changed(path)).unwrap();
        let AdmittedFileEvent::Symlink {
            file_id,
            entry,
            tree_changed,
            ..
        } = admitted
        else {
            panic!("dangling symlink must be admitted without dereferencing");
        };
        assert!(tree_changed);
        assert_eq!(file_id, Some(FilePathId::new("current")));
        assert!(matches!(entry, TreeEntry::Symlink { .. }));
        assert_eq!(
            read_tree_entry_bytes(&state, entry),
            b"../releases/not-present"
        );
        assert_eq!(tree_entry(&state, "current"), Some(entry));
    }

    #[cfg(unix)]
    #[test]
    fn admission_skips_untracked_special_but_rejects_tracked_type_loss() {
        use std::os::unix::net::UnixListener;

        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        let untracked = repo.path().join("untracked.sock");
        let _untracked_listener = UnixListener::bind(&untracked).unwrap();
        assert!(matches!(
            admit_file_event(&state, &FileEvent::Changed(untracked)).unwrap(),
            AdmittedFileEvent::Ignored
        ));
        assert!(tree_entry(&state, "untracked.sock").is_none());

        let tracked = repo.path().join("tracked.sock");
        std::fs::write(&tracked, b"regular before type change").unwrap();
        admit_file_event(&state, &FileEvent::Changed(tracked.clone())).unwrap();
        let old_entry = tree_entry(&state, "tracked.sock").unwrap();
        std::fs::remove_file(&tracked).unwrap();
        let _tracked_listener = UnixListener::bind(&tracked).unwrap();

        // The walk itself refuses: a tracked path Kin cannot represent makes
        // the scan incomplete, so there is no completion proof to publish with
        // and graph truth is retained.
        let error = admit_file_event(&state, &FileEvent::Changed(tracked))
            .expect_err("tracked special type must fail instead of erasing graph truth");
        assert!(
            error
                .to_string()
                .contains("tracked path changed to an unsupported special filesystem entry"),
            "{error}"
        );
        assert_eq!(tree_entry(&state, "tracked.sock"), Some(old_entry));
    }

    /// A watcher event for host content the repository has never tracked is
    /// declined outright, and the decline is published.
    ///
    /// The path could not be admitted, because ambient observation may revise
    /// graph-owned history but never enlarge it, and it could not be enriched
    /// either, because the revalidation compares host bytes against a tree
    /// entry authority does not hold. The loop deferred it
    /// instead, and every retry bought another complete exact-tree admission
    /// over the whole working copy that arrived at the identical refusal: the
    /// backlog never emptied, the status never returned to idle, the reported
    /// backlog age climbed without bound, and a flagship store spent a core
    /// rescanning itself for as long as the daemon lived.
    #[test]
    fn an_ambient_event_admits_new_host_content_it_observed() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let written = repo.path().join("brand_new.rs");
        std::fs::write(&written, b"pub fn brand_new() -> u32 { 1 }\n").unwrap();

        let admitted = admit_file_event_ambient(&state, &FileEvent::Changed(written)).unwrap();
        let AdmittedFileEvent::Regular { tree_changed, .. } = admitted else {
            panic!("an observed new file must be admitted, not declined: {admitted:?}");
        };
        assert!(
            tree_changed,
            "the admission that carried this path must be reported as having moved the tree"
        );
        assert!(
            tree_entry(&state, "brand_new.rs").is_some(),
            "writing a file is what makes it queryable; no command should be needed"
        );

        // Nothing is left for a surface to explain: the file a reader would
        // have gone looking for is in the tree.
        let report = state
            .background_work
            .reconcile()
            .report(std::time::Instant::now());
        assert_eq!(report.untracked_path_count, 0);
        assert!(report.untracked_paths_sample.is_empty());
        assert!(!report.degraded(), "{:?}", report.degraded_reasons());
        assert!(
            !report
                .notices()
                .iter()
                .any(|notice| notice.contains("brand_new.rs")),
            "no surface may call an admitted path untracked: {:?}",
            report.notices()
        );
    }

    /// The delta bound, and the test that fails if anyone widens the predicate.
    ///
    /// Admission follows the observation, not the walk. Both files are equally
    /// admissible and the complete scan met both, so the only thing separating
    /// them is that a watcher saw one of them. Widening the ambient predicate to
    /// take everything the walk met would make one host notification pay for a
    /// complete import of the working copy, which is the cost this bound exists
    /// to refuse. If this test ever fails on the second file being admitted,
    /// that is the regression and not a stale assertion.
    #[test]
    fn an_ambient_event_admits_only_what_its_observation_covers() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let observed = repo.path().join("observed.rs");
        std::fs::write(&observed, b"pub fn observed() -> u32 { 1 }\n").unwrap();
        std::fs::write(
            repo.path().join("unobserved.rs"),
            b"pub fn unobserved() -> u32 { 2 }\n",
        )
        .unwrap();

        let admitted = admit_file_event_ambient(&state, &FileEvent::Changed(observed)).unwrap();
        assert!(
            matches!(admitted, AdmittedFileEvent::Regular { .. }),
            "the observed file is admitted: {admitted:?}"
        );
        assert!(tree_entry(&state, "observed.rs").is_some());
        assert!(
            tree_entry(&state, "unobserved.rs").is_none(),
            "one event is no evidence about a path nothing observed"
        );

        let report = state
            .background_work
            .reconcile()
            .report(std::time::Instant::now());
        assert_eq!(
            report.untracked_path_count, 1,
            "exactly the file no observation covered is reported"
        );
        assert_eq!(report.untracked_paths_sample, vec!["unobserved.rs"]);
        assert!(
            report
                .notices()
                .iter()
                .any(|notice| notice.contains("unobserved.rs") && notice.contains("kin admit")),
            "the notice must name the path and the command that recovers it: {:?}",
            report.notices()
        );
    }

    /// Read the repository-authority generation one admission would advance.
    ///
    /// Every committed repository transaction advances it by exactly one, and
    /// preparing that successor plus persisting the store is the O(store) cost
    /// this whole seam exists to stop paying twice, so the generation is a
    /// direct count of successors rather than a proxy for one.
    fn authority_generation(state: &DaemonState) -> u64 {
        current_authority_admission(state).unwrap().0.generation
    }

    /// The ambient watcher path publishes its own successor. Nothing about the
    /// commit seam's deferral is allowed to reach it: an ambient tick has no
    /// later transaction to carry its tree, so a tick that stopped publishing
    /// would leave every observed write outside repository authority.
    #[test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    fn an_ambient_tick_publishes_its_own_authority_successor() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            repo.path().join("ambient.rs"),
            b"pub fn ambient() -> u32 { 1 }\n",
        )
        .unwrap();
        let repo_path = test_repo_path("ambient.rs");
        let observation = std::iter::once(repo_path.clone()).collect::<BTreeSet<_>>();

        let before = authority_generation(&state);
        let admission =
            exact_tree_admission(&state, Some(&observation), TreePublication::Standalone).unwrap();

        assert!(
            admission.deferred_tree.is_none(),
            "a standalone admission owns its publication and defers nothing"
        );
        assert_eq!(
            authority_generation(&state) - before,
            1,
            "the tick must publish exactly one repository-authority successor"
        );
        assert!(
            state
                .graph
                .resolved_tree()
                .artifact_at_path(&repo_path)
                .is_some(),
            "the derived graph carries the admitted path"
        );
    }

    /// The commit seam derives the same transition and publishes nothing, so
    /// its caller can carry the tree in the transaction that publishes the
    /// change. The graph still advances: the caller's transaction is what
    /// closes the gap, and the coordination gate it holds spans both.
    #[test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    fn a_deferring_admission_advances_no_authority_generation() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            repo.path().join("deferred.rs"),
            b"pub fn deferred() -> u32 { 1 }\n",
        )
        .unwrap();
        let repo_path = test_repo_path("deferred.rs");

        let before = authority_generation(&state);
        let admission =
            exact_tree_admission(&state, None, TreePublication::DeferredToCaller).unwrap();

        assert!(
            !admission.deltas.is_empty(),
            "the working copy moved, so the admission must plan a transition"
        );
        let deferred = admission
            .deferred_tree
            .expect("a deferring admission hands its transition back to the caller");
        assert_eq!(
            authority_generation(&state),
            before,
            "nothing may be published until the caller's own transaction publishes it"
        );
        assert!(
            state
                .graph
                .resolved_tree()
                .artifact_at_path(&repo_path)
                .is_some(),
            "the derived graph carries the admitted path so the commit can plan against it"
        );

        // Closing the deferral is what a commit that never reaches authority
        // does, and it must leave exactly the state a standalone admission
        // would have.
        publish_deferred_tree_after_failure(&state, &deferred);
        assert_eq!(
            authority_generation(&state) - before,
            1,
            "closing the deferral publishes the one successor it withheld"
        );
    }

    /// Move repository authority while a caller is holding an open deferral.
    ///
    /// Publishes `desired` as this workspace's tree through the same seam every
    /// admission publishes through, which advances the authority roots the
    /// deferral was planned against. Nothing else has to cooperate to produce
    /// the double failure: the deferral's own publication compare-and-swaps on
    /// those roots and refuses rather than replanning a stale desired tree onto
    /// newer authority, which is exactly what a concurrent authority write does
    /// to it in production.
    fn publish_authority_tree_out_of_band(state: &DaemonState, desired: kin_model::ResolvedTree) {
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
                .unwrap();
        let (expected_roots, previous_tree) = {
            let authority = context.open().unwrap();
            let lease = authority.read_authority();
            let previous = lease
                .metadata()
                .workspaces
                .iter()
                .find(|workspace| workspace.workspace_id == context.workspace_id())
                .map(|workspace| workspace.tree.clone())
                .unwrap_or_default();
            (lease.roots().clone(), previous)
        };
        let admitted = crate::repository_commit::admitted_workspace_tree_for_test(
            state.layout.working_dir(),
            expected_roots,
            previous_tree,
            desired,
        );
        crate::repository_commit::publish_workspace_tree(
            state.blobs.as_ref(),
            &context,
            &admitted,
            kin_model::OperationId::new(),
            kin_model::AuthorId::new("out-of-band-authority-writer"),
        )
        .expect("the fixture's own authority write must succeed")
        .expect("it has to move authority, or the deferral below would still publish cleanly");
    }

    /// The double failure, and the reset that ends it.
    ///
    /// A commit that fails publishes its deferred tree standalone on the way
    /// out. When that publication fails too there is nothing left to publish, so
    /// the derived graph is returned to the tree repository authority holds and
    /// the next admission plans out of a tree the two agree on. Before that
    /// reset the graph stayed ahead, every later admission was refused against
    /// the mismatched tree, and only restarting the daemon cleared it.
    #[test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    fn a_failed_restoring_publication_resets_the_graph_to_the_authority_tree() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(repo.path().join("base.rs"), b"pub fn base() -> u32 { 1 }\n").unwrap();
        exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
        let baseline = authority_generation(&state);

        std::fs::write(
            repo.path().join("carried.rs"),
            b"pub fn carried() -> u32 { 2 }\n",
        )
        .unwrap();
        let admission =
            exact_tree_admission(&state, None, TreePublication::DeferredToCaller).unwrap();
        let deferred = admission
            .deferred_tree
            .expect("the admission defers its transition to this caller");
        assert_eq!(
            authority_generation(&state),
            baseline,
            "nothing may be published while the deferral is open"
        );
        assert!(
            state
                .background_work
                .reconcile_report(Instant::now())
                .deferred_tree_wedge
                .is_none(),
            "the fixture reported a wedge before one happened"
        );

        // The second failure. Authority moves under the open deferral, so the
        // publication that would restore it has no valid transition left.
        publish_authority_tree_out_of_band(&state, kin_model::ResolvedTree::default());
        publish_deferred_tree_after_failure(&state, &deferred);

        assert_eq!(
            state.graph.resolved_tree(),
            authority_workspace_tree(&state).unwrap(),
            "a publication with nothing left to try must return the derived graph to the tree \
             repository authority holds"
        );
        let report = state.background_work.reconcile_report(Instant::now());
        assert!(
            report.deferred_tree_wedge.is_none(),
            "a daemon whose graph agrees with authority again needs no restart: {:?}",
            report.deferred_tree_wedge
        );
        assert!(!report.degraded(), "{:?}", report.degraded_reasons());

        // The reset is real rather than cosmetic. The next admission plans out
        // of a tree authority accepts, so it publishes instead of being refused
        // against a mismatch nobody could clear without restarting.
        std::fs::write(
            repo.path().join("later.rs"),
            b"pub fn later() -> u32 { 3 }\n",
        )
        .unwrap();
        let admission = exact_tree_admission(&state, None, TreePublication::Standalone)
            .expect("a reset daemon admits the next transition rather than refusing it");
        assert!(
            !admission.deltas.is_empty(),
            "the working copy moved, so the admission must plan a transition"
        );
        assert_eq!(
            state.graph.resolved_tree(),
            authority_workspace_tree(&state).unwrap(),
            "the admission that followed the reset left both trees agreeing"
        );
    }

    /// FIR-2495. A refused admission must not leave the daemon holding a
    /// workspace plan repository authority will reject forever.
    ///
    /// The credential scanner refuses untracked sensitive content inside the
    /// repository transaction, so the commit carrying it fails and the
    /// publication restoring its deferred tree carries the same artifact and
    /// fails for the same reason. Publishing forward is the recovery that cannot
    /// work here, and before the reset the derived graph stayed ahead of
    /// authority for the life of the daemon: the next commit reported a tree
    /// mismatch, `kin admit` reported that nothing had changed while authority
    /// carried none of it, the commit after that reported a projection conflict
    /// on a path that was simply there, and `kin status` and `kin graph status`
    /// disagreed about the artifact count seconds apart.
    #[tokio::test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    async fn a_scanner_refused_admission_rolls_back_so_the_next_commit_proceeds() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            repo.path().join("store.py"),
            b"def store():\n    return 1\n",
        )
        .unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();
        let baseline_generation = authority_generation(&state);
        let baseline_tree = state.graph.resolved_tree();
        assert_eq!(
            baseline_tree,
            authority_workspace_tree(&state).unwrap(),
            "the fixture must start with the two trees agreeing"
        );

        // The stranger's situation: content the credential scanner refuses,
        // written into the working copy and never tracked.
        std::fs::write(
            repo.path().join("search.py"),
            b"def connect():\n    password = \"s3cret-notekeeper-value\"\n    return password\n",
        )
        .unwrap();

        // The commit path. It admits the whole working copy and defers the tree
        // transition to the transaction that publishes its change.
        let deferred = sync_filesystem_with_graph_deferring_tree_publication(&state)
            .await
            .unwrap()
            .expect("the commit seam defers its transition to the caller");
        assert_eq!(
            authority_generation(&state),
            baseline_generation,
            "nothing may be published while the deferral is open"
        );
        assert!(
            state
                .graph
                .resolved_tree()
                .artifact_at_path(&test_repo_path("search.py"))
                .is_some(),
            "the deferring admission advances the derived graph so the commit can plan against it"
        );
        assert!(
            !entity_ids_for(&state, "search.py").is_empty(),
            "the fixture needs the refused artifact enriched, or the eviction below proves nothing"
        );

        // Name the refusal the fixture rests on. A scanner that stopped
        // refusing this content would leave the publication below succeeding,
        // and every assertion after it would pass for the wrong reason, so the
        // test says outright which refusal it is reproducing. This call changes
        // nothing: a refused publication advances no authority generation.
        let refusal = publish_exact_workspace_tree(&state, &deferred)
            .expect_err("the credential scanner must refuse the artifact this fixture writes");
        assert!(
            refusal.to_string().contains("CredentialAssignment"),
            "the fixture reproduces the credential scanner's refusal: {refusal}"
        );

        // What a commit refused by the scanner does on its way out. The
        // publication restoring the deferred tree carries the same refused
        // artifact, so it is refused too and there is nothing left to publish.
        let version_before = state.vfs_version.load(Ordering::SeqCst);
        publish_deferred_tree_after_failure(&state, &deferred);

        assert!(
            state.vfs_version.load(Ordering::SeqCst) > version_before,
            "a reset that took artifacts out of the graph must retire the projection readers \
             holding them and arm background persistence, or a restart reloads the graph that \
             was ahead"
        );

        assert_eq!(
            authority_generation(&state),
            baseline_generation,
            "a refused admission publishes no authority successor"
        );
        assert_eq!(
            state.graph.resolved_tree(),
            baseline_tree,
            "a refused admission must roll the derived graph back to the pre-attempt tree"
        );
        assert_eq!(
            state.graph.resolved_tree(),
            authority_workspace_tree(&state).unwrap(),
            "the two trees the status surfaces read must agree again"
        );
        assert!(
            entity_ids_for(&state, "search.py").is_empty(),
            "the rollback must take the enrichment derived from the artifact it removed"
        );
        let report = state.background_work.reconcile_report(Instant::now());
        assert!(
            report.deferred_tree_wedge.is_none(),
            "a daemon that rolled back needs no restart: {:?}",
            report.deferred_tree_wedge
        );
        assert!(!report.degraded(), "{:?}", report.degraded_reasons());

        // The next ordinary commit proceeds. Removing the refused artifact is
        // what a user does after reading the refusal, and before the rollback
        // this is the point at which the daemon reported a projection conflict
        // about a path that was simply there.
        std::fs::remove_file(repo.path().join("search.py")).unwrap();
        std::fs::write(
            repo.path().join("later.py"),
            b"def later():\n    return 3\n",
        )
        .unwrap();
        sync_filesystem_with_graph(&state)
            .await
            .expect("a rolled-back daemon admits the next transition rather than refusing it");

        assert_eq!(
            authority_generation(&state) - baseline_generation,
            1,
            "the admission after the rollback publishes exactly one authority successor"
        );
        let after = state.graph.resolved_tree();
        assert_eq!(
            after,
            authority_workspace_tree(&state).unwrap(),
            "both status surfaces must report the same tree after the recovery"
        );
        assert!(
            after
                .artifact_at_path(&test_repo_path("later.py"))
                .is_some(),
            "the work that followed the refusal is what had to become committable"
        );
    }

    /// The falsification, and the ordinary case beside it. A commit that fails
    /// is routine, and the publication restoring its deferred tree normally
    /// succeeds, leaving exactly the state a standalone admission would have.
    /// A flag that fired on the single failure would report every failed commit
    /// as a daemon needing a restart.
    #[test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    fn a_restored_deferral_leaves_nothing_wedged_and_clears_an_earlier_wedge() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            repo.path().join("restored.rs"),
            b"pub fn restored() -> u32 { 1 }\n",
        )
        .unwrap();
        let admission =
            exact_tree_admission(&state, None, TreePublication::DeferredToCaller).unwrap();
        let deferred = admission
            .deferred_tree
            .expect("the admission defers its transition to this caller");

        publish_deferred_tree_after_failure(&state, &deferred);

        let report = state.background_work.reconcile_report(Instant::now());
        assert!(
            report.deferred_tree_wedge.is_none(),
            "a deferral that closed is not a wedge: {:?}",
            report.deferred_tree_wedge
        );
        assert!(!report.degraded(), "{:?}", report.degraded_reasons());
        assert!(
            serde_json::to_value(&report).unwrap()["deferred_tree_wedge"].is_null(),
            "a healthy daemon must serialize no wedge field at all"
        );

        // A daemon carrying an earlier wedge is cleared by a deferral that does
        // close. Publishing planned against the authority tree and advanced it,
        // which a graph running ahead of authority cannot do.
        state
            .background_work
            .reconcile()
            .record_deferred_tree_wedge("an earlier restoring publication failed", Instant::now());
        std::fs::write(
            repo.path().join("second.rs"),
            b"pub fn second() -> u32 { 2 }\n",
        )
        .unwrap();
        let admission =
            exact_tree_admission(&state, None, TreePublication::DeferredToCaller).unwrap();
        let deferred = admission
            .deferred_tree
            .expect("the admission defers its transition to this caller");
        publish_deferred_tree_after_failure(&state, &deferred);
        assert!(
            state
                .background_work
                .reconcile_report(Instant::now())
                .deferred_tree_wedge
                .is_none(),
            "a publication that reached authority resolves the divergence a wedge names"
        );
    }

    /// A collapsed commit publishes the tree its own walk proved, or none.
    ///
    /// The completion proof rides along as a value only a finished walk can
    /// mint, which is what stops a collapsed commit being assembled from a
    /// partial one. That alone is not enough: a token says some walk finished,
    /// not which tree it observed. So the proof is checked against the plan,
    /// and this drives the two apart to watch the check fire. The graph moves
    /// after the admission returns, exactly as a stray in-process tree
    /// mutation between admission and publication would move it, and the
    /// commit that would then publish an unobserved transition is refused.
    #[test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    fn a_collapsed_commit_refuses_a_tree_its_walk_did_not_observe() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            repo.path().join("observed.rs"),
            b"pub fn observed() -> u32 { 1 }\n",
        )
        .unwrap();

        let admission =
            exact_tree_admission(&state, None, TreePublication::DeferredToCaller).unwrap();
        let deferred = admission
            .deferred_tree
            .expect("the admission defers its transition to this caller");

        // Move the derived tree after the walk proved it, so the plan below
        // targets a tree no walk observed.
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: kin_model::ArtifactId::new(),
                    new: kin_model::LocatedEntry::new(
                        test_repo_path("never_walked.rs"),
                        TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x7c; 20])),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();

        let authority_context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
                .unwrap();
        let plan = crate::repository_commit::plan_native_commit(
            &state.graph,
            state.blobs.as_ref(),
            &authority_context,
            kin_model::OperationId::new(),
            kin_model::Timestamp::now(),
            kin_model::AuthorId::new("collapsed-proof-test"),
            "publish a tree no walk observed".to_string(),
        )
        .unwrap();

        let error = crate::repository_commit::commit_native_plan_with_observed_target_tree(
            &state.layout,
            state.blobs.as_ref(),
            &authority_context,
            plan,
            &deferred,
        )
        .expect_err("a plan targeting an unobserved tree must be refused");
        assert!(
            error.to_string().contains("no walk observed"),
            "the refusal must name what went wrong: {error}"
        );
    }

    /// FIR-2495 ask 2. A daemon whose graph outran authority names the recovery.
    ///
    /// The reset above closes the route this fleet has actually seen, and a
    /// reset that fails itself leaves the daemon in exactly this state. What the
    /// user meets then is this refusal, and on its own it described a mismatch
    /// without saying that restarting is what clears it, which is how four
    /// consecutive errors named symptoms and none named the cause.
    #[test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    fn a_commit_planned_out_of_a_stale_graph_tree_names_the_daemon_restart() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(repo.path().join("base.rs"), b"pub fn base() -> u32 { 1 }\n").unwrap();
        exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
        std::fs::write(
            repo.path().join("carried.rs"),
            b"pub fn carried() -> u32 { 1 }\n",
        )
        .unwrap();
        let admission =
            exact_tree_admission(&state, None, TreePublication::DeferredToCaller).unwrap();
        let deferred = admission
            .deferred_tree
            .expect("the admission defers its transition to this caller");

        // Move repository authority under the open deferral, which is what
        // leaves the walk's own prior tree and the plan's prior tree apart.
        publish_authority_tree_out_of_band(&state, kin_model::ResolvedTree::default());

        let authority_context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
                .unwrap();
        let plan = crate::repository_commit::plan_native_commit(
            &state.graph,
            state.blobs.as_ref(),
            &authority_context,
            kin_model::OperationId::new(),
            kin_model::Timestamp::now(),
            kin_model::AuthorId::new("stale-graph-tree-test"),
            "publish out of a tree authority no longer holds".to_string(),
        )
        .unwrap();

        let error = crate::repository_commit::commit_native_plan_with_observed_target_tree(
            &state.layout,
            state.blobs.as_ref(),
            &authority_context,
            plan,
            &deferred,
        )
        .expect_err("a plan whose prior tree is not the walk's prior tree must be refused");
        let error = error.to_string();
        assert!(
            error.contains("planned out of a different workspace tree"),
            "the refusal must still name the mismatch: {error}"
        );
        assert!(
            error.contains("kin daemon stop"),
            "the refusal must name the one command that clears this: {error}"
        );
        assert!(
            error.contains("ahead of repository authority"),
            "the refusal must name the state, not just the remedy: {error}"
        );
    }

    /// The livelock signature stays dead, in the counters that carried it.
    ///
    /// The earlier spin was a closed loop: an unadmitted path failed the host
    /// revalidation, the loop deferred it, and every retry bought another
    /// complete admission over the whole working copy that reached the identical
    /// refusal. Admission breaks it at the first link, so this asserts the link
    /// is broken rather than that the symptom is absent. A second tick over the
    /// same observation plans nothing, and the revalidation `run_loop` defers on
    /// now succeeds.
    #[test]
    fn a_second_ambient_tick_for_an_admitted_path_plans_nothing() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let path = repo.path().join("brand_new.rs");
        std::fs::write(&path, b"pub fn brand_new() -> u32 { 1 }\n").unwrap();
        let repo_path = test_repo_path("brand_new.rs");
        let observation = std::iter::once(repo_path.clone()).collect::<BTreeSet<_>>();

        let first =
            exact_tree_admission(&state, Some(&observation), TreePublication::Standalone).unwrap();
        assert!(
            first.changed_paths.contains(&repo_path),
            "the first tick admits the observed path"
        );

        let second =
            exact_tree_admission(&state, Some(&observation), TreePublication::Standalone).unwrap();
        assert!(
            second.deltas.is_empty() && second.changed_paths.is_empty(),
            "a settled path must plan nothing on the next tick: {:?}",
            second.deltas
        );

        // `run_loop` defers precisely when this returns false, which is the step
        // that opened the retry ladder.
        assert!(
            host_entry_matches_graph(&state, &path, &repo_path).unwrap(),
            "an admitted path must revalidate, so no event for it can be deferred"
        );

        let report = state
            .background_work
            .reconcile()
            .report(std::time::Instant::now());
        assert_eq!(report.untracked_path_count, 0);
        assert_eq!(report.admission_failures, 0);
        assert!(!report.degraded(), "{:?}", report.degraded_reasons());
    }

    /// The rules still decide, and they decide once.
    ///
    /// Excluded content is not in the walk at all, so admitting observed paths
    /// cannot reach it however the watcher behaves. The verdict stays terminal,
    /// nothing enters the tree, and the excluded content is disclosed as a count
    /// rather than as a list of every derived file in the working copy.
    #[test]
    fn an_ignored_new_path_is_still_declined_once() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        // The rule file is itself new host content, and writing it is what puts
        // it in force. It is admitted like any other observed file, which is why
        // the ambient event for it comes first.
        let rules = repo.path().join(".kinignore");
        std::fs::write(&rules, b"secrets\n").unwrap();
        admit_file_event_ambient(&state, &FileEvent::Changed(rules)).unwrap();
        assert!(
            tree_entry(&state, ".kinignore").is_some(),
            "a rule file is repository content and is admitted like any other"
        );

        std::fs::create_dir(repo.path().join("secrets")).unwrap();
        let ignored = repo.path().join("secrets/key.rs");
        std::fs::write(&ignored, b"pub fn key() -> u32 { 1 }\n").unwrap();

        let admitted = admit_file_event_ambient(&state, &FileEvent::Changed(ignored)).unwrap();
        assert!(
            matches!(admitted, AdmittedFileEvent::Ignored),
            "an excluded path is declined, not admitted: {admitted:?}"
        );
        assert!(tree_entry(&state, "secrets/key.rs").is_none());

        let report = state
            .background_work
            .reconcile()
            .report(std::time::Instant::now());
        assert_eq!(
            report.untracked_path_count, 0,
            "excluded content is not admissible content waiting for a pass"
        );
        assert!(
            report.ignored_path_count > 0,
            "the walk must say it left content unobserved: {report:?}"
        );
        assert!(
            !report.degraded(),
            "ignoring content is a rule taking effect, not a fault: {:?}",
            report.degraded_reasons()
        );
        assert!(
            report
                .notices()
                .iter()
                .any(|notice| notice.contains("ignore rules") && notice.contains(".kinignore")),
            "the notice must send the reader to the rules: {:?}",
            report.notices()
        );
    }

    /// The verdict that remains after observed paths are admitted: admissible
    /// content the complete walk never met, such as a file created after its own
    /// directory was walked. It is still terminal, because a deferral would
    /// reopen the ladder that never converged.
    #[test]
    fn content_the_walk_never_met_is_still_declined_terminally() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let missed = repo.path().join("raced.rs");

        // The admission runs against a working copy that does not hold the file,
        // exactly as a walk that finished before the file landed would have.
        let observation = BTreeSet::new();
        let admission =
            exact_tree_admission(&state, Some(&observation), TreePublication::Standalone).unwrap();
        std::fs::write(&missed, b"pub fn raced() -> u32 { 1 }\n").unwrap();

        let admitted = admit_file_event_with_exact_tree(
            &state,
            &FileEvent::Changed(missed),
            &admission.changed_paths,
        )
        .unwrap();
        let AdmittedFileEvent::Untracked { repo_path } = admitted else {
            panic!("content no admission carried must be declined: {admitted:?}");
        };
        assert_eq!(repo_path, test_repo_path("raced.rs"));
        assert!(tree_entry(&state, "raced.rs").is_none());
    }

    /// The explicit seam is bounded by nothing, which is what makes it the
    /// recovery surface. It admits a path the working copy holds whether or not
    /// anything ever observed that path arriving, so a store whose watcher
    /// missed a file is one command away from carrying it.
    #[test]
    fn an_explicit_seam_still_admits_the_same_untracked_path() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let path = repo.path().join("brand_new.rs");
        std::fs::write(&path, b"pub fn brand_new() -> u32 { 2152 }\n").unwrap();

        let admitted = admit_file_event(&state, &FileEvent::Changed(path)).unwrap();
        let AdmittedFileEvent::Regular { tree_changed, .. } = admitted else {
            panic!("an explicit seam admits untracked host content: {admitted:?}");
        };
        assert!(tree_changed);
        assert!(tree_entry(&state, "brand_new.rs").is_some());
    }

    /// The disclosure is the loop's answer to why a file is not queryable, so it
    /// has to stop being that answer the moment a commit admits the path.
    ///
    /// Nothing else would clear it. A commit reaches authority through the
    /// explicit seam and produces no watcher event of its own, so on a working
    /// copy nobody is editing there is no next ambient tick to replace the
    /// record. The surface would keep naming a path whose entities resolve,
    /// which is the same misdirection the disclosure exists to remove.
    #[test]
    fn admitting_a_declined_path_clears_its_disclosure_without_another_host_event() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let observed = repo.path().join("observed.rs");
        std::fs::write(&observed, b"pub fn observed() -> u32 { 1 }\n").unwrap();
        std::fs::write(
            repo.path().join("unobserved.rs"),
            b"pub fn unobserved() -> u32 { 2 }\n",
        )
        .unwrap();

        admit_file_event_ambient(&state, &FileEvent::Changed(observed)).unwrap();
        let declined = state
            .background_work
            .reconcile()
            .report(std::time::Instant::now());
        assert_eq!(declined.untracked_path_count, 1);
        assert_eq!(declined.untracked_paths_sample, vec!["unobserved.rs"]);

        // The commit seam, and nothing after it: no watcher event is delivered,
        // which is exactly the quiescent working copy the stale record survived
        // on.
        exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
        assert!(
            tree_entry(&state, "unobserved.rs").is_some(),
            "the seam must admit the path this disclosure was about"
        );

        let admitted = state
            .background_work
            .reconcile()
            .report(std::time::Instant::now());
        assert_eq!(
            admitted.untracked_path_count, 0,
            "a path repository authority now carries is not untracked host content"
        );
        assert!(admitted.untracked_paths_sample.is_empty());
        assert!(
            !admitted
                .notices()
                .iter()
                .any(|notice| notice.contains("unobserved.rs")),
            "no surface may keep calling an admitted path untracked: {:?}",
            admitted.notices()
        );
    }

    /// The control that keeps the decline narrow: once a path is tracked, an
    /// ambient watcher event for it is admitted exactly as before.
    #[test]
    fn an_ambient_event_for_a_tracked_path_is_still_admitted() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let path = repo.path().join("tracked.rs");
        std::fs::write(&path, b"pub fn tracked() -> u32 { 1 }\n").unwrap();
        admit_file_event(&state, &FileEvent::Changed(path.clone())).unwrap();
        let admitted_entry = tree_entry(&state, "tracked.rs").unwrap();

        std::fs::write(&path, b"pub fn tracked() -> u32 { 2 }\n").unwrap();
        let admitted = admit_file_event_ambient(&state, &FileEvent::Changed(path)).unwrap();
        let AdmittedFileEvent::Regular { tree_changed, .. } = admitted else {
            panic!("an edit to a tracked path must still be admitted: {admitted:?}");
        };
        assert!(tree_changed);
        assert_ne!(tree_entry(&state, "tracked.rs").unwrap(), admitted_entry);
        assert_eq!(
            state
                .background_work
                .reconcile()
                .report(std::time::Instant::now())
                .untracked_path_count,
            0,
            "a working copy holding only tracked paths reports none untracked"
        );
    }

    #[test]
    fn admission_never_expands_graph_owned_gitlink_checkout() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let gitlink = TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x5a; 20]));
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: kin_model::ArtifactId::new(),
                    new: kin_model::LocatedEntry::new(test_repo_path("submodule"), gitlink),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        std::fs::create_dir_all(repo.path().join("submodule/src")).unwrap();
        let nested = repo.path().join("submodule/src/lib.rs");
        std::fs::write(&nested, b"host checkout is not Gitlink truth").unwrap();

        assert!(matches!(
            admit_file_event(&state, &FileEvent::Changed(nested)).unwrap(),
            AdmittedFileEvent::Ignored
        ));
        assert_eq!(tree_entry(&state, "submodule"), Some(gitlink));
        assert!(tree_entry(&state, "submodule/src/lib.rs").is_none());
    }

    /// Stage the shape of the branch-switch race without racing anything.
    ///
    /// A Gitlink stands, host content is written beneath it, the member is
    /// removed, and only then does the watcher event for that content reach
    /// admission. That is exactly what a switch produces when its watcher
    /// backlog outlives the transition, and the ordering here is fixed rather
    /// than raced, so the assertion does not depend on any timing.
    fn state_whose_gitlink_was_removed_under_a_pending_event(
        repo: &tempfile::TempDir,
    ) -> (Arc<DaemonState>, std::path::PathBuf) {
        let state = open_test_state(repo);
        let gitlink = TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x5a; 20]));
        let artifact_id = kin_model::ArtifactId::new();
        let member = test_repo_path("submodule");
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: kin_model::LocatedEntry::new(member.clone(), gitlink),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        std::fs::create_dir_all(repo.path().join("submodule/src")).unwrap();
        let nested = repo.path().join("submodule/src/lib.rs");
        std::fs::write(&nested, b"independent checkout content").unwrap();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id,
                    old: kin_model::LocatedEntry::new(member, gitlink),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        (state, nested)
    }

    /// The fix. The transition retired the member, so the host content beneath
    /// it stays out of the workspace however late its event arrives.
    #[test]
    fn a_retired_gitlink_keeps_its_host_subtree_out_of_ambient_admission() {
        let repo = tempfile::tempdir().unwrap();
        let (state, nested) = state_whose_gitlink_was_removed_under_a_pending_event(&repo);
        state
            .retired_graph_only_members
            .retire([&test_repo_path("submodule")]);

        let admitted = admit_file_event_ambient(&state, &FileEvent::Changed(nested)).unwrap();
        assert!(
            matches!(admitted, AdmittedFileEvent::Untracked { .. }),
            "content beneath a retired member is untracked, not admitted: {admitted:?}"
        );
        assert!(
            tree_entry(&state, "submodule/src/lib.rs").is_none(),
            "a removed Gitlink must not hand its host subtree to the workspace"
        );
        let report = state
            .background_work
            .reconcile()
            .report(std::time::Instant::now());
        assert_eq!(
            report.untracked_paths_sample,
            vec!["submodule/src/lib.rs"],
            "the content is reported rather than hidden, so an explicit seam can take it"
        );
    }

    /// The control that proves the assertion above can fail. Without the
    /// retirement, the identical sequence admits the nested content, which is
    /// the defect: the workspace goes ahead of the base a switch just made it
    /// level with, and the next switch refuses.
    #[test]
    fn without_the_retirement_a_removed_gitlink_leaks_its_host_subtree() {
        let repo = tempfile::tempdir().unwrap();
        let (state, nested) = state_whose_gitlink_was_removed_under_a_pending_event(&repo);

        admit_file_event_ambient(&state, &FileEvent::Changed(nested)).unwrap();
        assert!(
            tree_entry(&state, "submodule/src/lib.rs").is_some(),
            "this control exists to fail the day the leak stops reproducing without a retirement"
        );
    }

    /// An explicit admission seam takes what the retirement was holding back,
    /// and ambient observation resumes over the subtree afterwards.
    #[test]
    fn an_explicit_seam_sweeps_a_retired_subtree_and_ends_the_retirement() {
        let repo = tempfile::tempdir().unwrap();
        let (state, nested) = state_whose_gitlink_was_removed_under_a_pending_event(&repo);
        state
            .retired_graph_only_members
            .retire([&test_repo_path("submodule")]);

        admit_file_event(&state, &FileEvent::Changed(nested.clone())).unwrap();
        assert!(
            tree_entry(&state, "submodule/src/lib.rs").is_some(),
            "an explicit seam admits every host path the complete walk met"
        );
        assert!(
            state.retired_graph_only_members.snapshot().is_empty(),
            "the sweep is the caller saying the subtree is theirs"
        );

        std::fs::write(&nested, b"edited after the explicit sweep").unwrap();
        let admitted = admit_file_event_ambient(&state, &FileEvent::Changed(nested)).unwrap();
        let AdmittedFileEvent::Regular { tree_changed, .. } = admitted else {
            panic!("an edit under a swept subtree is ordinary content now: {admitted:?}");
        };
        assert!(tree_changed);
    }

    /// A retirement is scoped to its own subtree. Nothing else in the working
    /// copy stops being ambiently admissible because one Gitlink went away.
    #[test]
    fn a_retirement_leaves_the_rest_of_the_working_copy_admissible() {
        let repo = tempfile::tempdir().unwrap();
        let (state, _) = state_whose_gitlink_was_removed_under_a_pending_event(&repo);
        state
            .retired_graph_only_members
            .retire([&test_repo_path("submodule")]);

        let sibling = repo.path().join("sibling.rs");
        std::fs::write(&sibling, b"pub fn sibling() -> u32 { 1 }\n").unwrap();
        let admitted = admit_file_event_ambient(&state, &FileEvent::Changed(sibling)).unwrap();
        assert!(
            !matches!(admitted, AdmittedFileEvent::Untracked { .. }),
            "an unrelated new file is still admitted from the act of writing it: {admitted:?}"
        );
        assert!(tree_entry(&state, "sibling.rs").is_some());
    }

    #[tokio::test]
    async fn complete_sync_preserves_identity_for_rename_with_path_reuse() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let old_path = repo.path().join("compose.yaml");
        let destination = repo.path().join("deploy/compose.yaml");
        let original = b"services:\n  api:\n    image: original\n";
        let replacement = b"services:\n  worker:\n    image: replacement\n";
        std::fs::write(&old_path, original).unwrap();

        sync_filesystem_with_graph(&state).await.unwrap();
        let original_id = state
            .graph
            .resolved_tree()
            .artifact_id_at_path(&test_repo_path("compose.yaml"))
            .expect("initial artifact identity");

        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::rename(&old_path, &destination).unwrap();
        std::fs::write(&old_path, replacement).unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        let tree = state.graph.resolved_tree();
        assert_eq!(
            tree.artifact_id_at_path(&test_repo_path("deploy/compose.yaml")),
            Some(original_id),
            "the moved artifact must retain identity"
        );
        let replacement_id = tree
            .artifact_id_at_path(&test_repo_path("compose.yaml"))
            .expect("replacement artifact identity");
        assert_ne!(
            replacement_id, original_id,
            "path reuse must create a distinct artifact"
        );
        assert_eq!(
            read_tree_entry_bytes(
                &state,
                tree.get(&original_id).expect("moved artifact").entry
            ),
            original
        );
        assert_eq!(
            read_tree_entry_bytes(
                &state,
                tree.get(&replacement_id)
                    .expect("replacement artifact")
                    .entry
            ),
            replacement
        );
    }

    #[tokio::test]
    async fn complete_sync_retains_graph_truth_when_move_identity_is_ambiguous() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let old_path = repo.path().join("asset.bin");
        let bytes = b"\0opaque duplicate bytes";
        std::fs::write(&old_path, bytes).unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();
        let before = state.graph.resolved_tree();

        std::fs::write(repo.path().join("copy-a.bin"), bytes).unwrap();
        std::fs::write(repo.path().join("copy-b.bin"), bytes).unwrap();
        std::fs::remove_file(old_path).unwrap();
        let error = sync_filesystem_with_graph(&state)
            .await
            .expect_err("ambiguous identity must fail before graph mutation");

        assert!(error.to_string().contains("ambiguous repository identity"));
        assert_eq!(
            state.graph.resolved_tree(),
            before,
            "failed exact admission must retain the complete parent tree"
        );
    }

    #[tokio::test]
    async fn binary_reclassification_clears_source_facets_but_keeps_tree_truth() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        let path = repo.path().join("src/change.rs");
        std::fs::write(&path, "pub fn semantic_source() -> u8 { 1 }\n").unwrap();

        sync_filesystem_with_graph(&state).await.unwrap();
        assert!(state
            .graph
            .entity_bearing_file_paths()
            .contains(&"src/change.rs".to_string()));
        assert!(state
            .graph
            .get_opaque_artifact(&FilePathId::new("src/change.rs"))
            .unwrap()
            .is_none());

        let binary = b"\0\xff\x10not-source";
        std::fs::write(&path, binary).unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        let entry =
            tree_entry(&state, "src/change.rs").expect("binary file remains exact tree truth");
        assert!(matches!(
            entry,
            TreeEntry::Blob {
                executable: false,
                ..
            }
        ));
        assert_eq!(read_tree_entry_bytes(&state, entry), binary);
        assert!(!state
            .graph
            .entity_bearing_file_paths()
            .contains(&"src/change.rs".to_string()));
        assert!(state
            .graph
            .get_file_layout(&FilePathId::new("src/change.rs"))
            .unwrap()
            .is_none());
        assert!(state
            .graph
            .get_opaque_artifact(&FilePathId::new("src/change.rs"))
            .unwrap()
            .is_some());

        std::fs::write(&path, "pub fn semantic_source() -> u8 { 2 }\n").unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();
        assert!(state
            .graph
            .entity_bearing_file_paths()
            .contains(&"src/change.rs".to_string()));
        assert!(state
            .graph
            .get_opaque_artifact(&FilePathId::new("src/change.rs"))
            .unwrap()
            .is_none());
        assert!(tree_entry(&state, "src/change.rs").is_some());
    }

    /// A store born from bulk admission holds tree truth with no non-entity
    /// enrichment records, so nothing feeds the artifact embedding queue or the
    /// artifact text index and `kin embed` honestly reports "+0 artifacts".
    /// The coverage pass must recreate exactly the missing records from CAS
    /// bodies, leave entity sources alone, and be idempotent.
    #[cfg(feature = "embeddings")]
    #[tokio::test]
    async fn coverage_pass_recreates_missing_records_and_feeds_the_artifact_queue() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            repo.path().join("AGENTS.md"),
            "# Doctrine\n\nChecks That Cannot Fail live here, past any preview cap.\n",
        )
        .unwrap();
        std::fs::write(repo.path().join("main.py"), "def fail():\n    return 1\n").unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        let doc_id = FilePathId::new("AGENTS.md");
        assert!(state.graph.get_opaque_artifact(&doc_id).unwrap().is_some());

        // Deleting the record reproduces the shape bulk admission leaves
        // behind: the tree tracks the file, no enrichment facet exists.
        state.graph.delete_opaque_artifact(&doc_id).unwrap();
        assert_eq!(state.graph.artifact_count(), 0);
        assert!(tree_entry(&state, "AGENTS.md").is_some());

        let created = ensure_non_entity_enrichment_coverage(&state).unwrap();
        assert_eq!(
            created, 1,
            "the doc regains its record; the entity source must not gain one"
        );
        let record = state
            .graph
            .get_opaque_artifact(&doc_id)
            .unwrap()
            .expect("coverage pass recreates the opaque record");
        assert!(
            record
                .text_preview
                .as_deref()
                .unwrap_or_default()
                .contains("Checks That Cannot Fail"),
            "recreated record must retain the body text retrieval indexes"
        );
        assert!(state
            .graph
            .get_opaque_artifact(&FilePathId::new("main.py"))
            .unwrap()
            .is_none());
        assert_eq!(state.graph.artifact_count(), 1);

        assert_eq!(
            ensure_non_entity_enrichment_coverage(&state).unwrap(),
            0,
            "a second pass over full coverage creates nothing"
        );

        // The recreated record is exactly what the artifact embedding queue
        // keys on, so the backfill can now see the file.
        state.graph.queue_missing_artifacts_for_embedding();
        assert!(
            state.graph.pending_artifact_embeddings() >= 1,
            "recreated record must enter the artifact embedding backfill"
        );
    }

    #[tokio::test]
    async fn startup_sync_keeps_universal_entries_and_delete_clears_tree_and_facets() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let compose_path = repo.path().join("compose.yaml");
        let notes_path = repo.path().join("release.notes");
        std::fs::write(
            &compose_path,
            "services:\n  api:\n    image: example/api:latest\n",
        )
        .unwrap();
        std::fs::write(&notes_path, "operator notes\n").unwrap();

        sync_filesystem_with_graph(&state).await.unwrap();
        let before = state.graph.resolved_tree();
        assert_eq!(before.len(), 2);
        assert!(state
            .graph
            .get_structured_artifact(&FilePathId::new("compose.yaml"))
            .unwrap()
            .is_some());
        assert!(state
            .graph
            .get_opaque_artifact(&FilePathId::new("release.notes"))
            .unwrap()
            .is_some());

        // A startup/tick scan over an unchanged universal tree must not purge
        // entries merely because they have no language parser.
        sync_filesystem_with_graph(&state).await.unwrap();
        assert_eq!(state.graph.resolved_tree(), before);
        assert!(state
            .graph
            .get_opaque_artifact(&FilePathId::new("release.notes"))
            .unwrap()
            .is_some());

        std::fs::remove_file(&notes_path).unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();
        assert!(tree_entry(&state, "release.notes").is_none());
        assert!(state
            .graph
            .get_opaque_artifact(&FilePathId::new("release.notes"))
            .unwrap()
            .is_none());
        assert!(tree_entry(&state, "compose.yaml").is_some());
    }

    #[test]
    fn dedup_keeps_last_event_per_path() {
        let events = vec![
            FileEvent::Changed(PathBuf::from("/a.rs")),
            FileEvent::Changed(PathBuf::from("/b.rs")),
            FileEvent::Changed(PathBuf::from("/a.rs")), // supersedes first /a.rs
        ];
        let deduped = dedup_file_events(events);
        assert_eq!(deduped.len(), 2);
        // /b.rs comes first (index 1), /a.rs second (index 2)
        assert!(matches!(&deduped[0], FileEvent::Changed(p) if p == &PathBuf::from("/b.rs")));
        assert!(matches!(&deduped[1], FileEvent::Changed(p) if p == &PathBuf::from("/a.rs")));
    }

    #[test]
    fn dedup_removed_supersedes_changed() {
        let events = vec![
            FileEvent::Changed(PathBuf::from("/a.rs")),
            FileEvent::Removed(PathBuf::from("/a.rs")), // supersedes Changed
        ];
        let deduped = dedup_file_events(events);
        assert_eq!(deduped.len(), 1);
        assert!(matches!(&deduped[0], FileEvent::Removed(p) if p == &PathBuf::from("/a.rs")));
    }

    #[test]
    fn dedup_changed_after_removed_means_recreated() {
        let events = vec![
            FileEvent::Removed(PathBuf::from("/a.rs")),
            FileEvent::Changed(PathBuf::from("/a.rs")), // file was recreated
        ];
        let deduped = dedup_file_events(events);
        assert_eq!(deduped.len(), 1);
        assert!(matches!(&deduped[0], FileEvent::Changed(p) if p == &PathBuf::from("/a.rs")));
    }

    #[test]
    fn dedup_preserves_different_paths() {
        let events = vec![
            FileEvent::Changed(PathBuf::from("/a.rs")),
            FileEvent::Changed(PathBuf::from("/b.rs")),
            FileEvent::Removed(PathBuf::from("/c.rs")),
        ];
        let deduped = dedup_file_events(events);
        assert_eq!(deduped.len(), 3);
    }

    #[test]
    fn dedup_empty_input() {
        let deduped = dedup_file_events(vec![]);
        assert!(deduped.is_empty());
    }

    #[test]
    fn retained_backlog_processes_every_event_across_bounded_batches() {
        let mut pending = VecDeque::new();
        let events = (0..6)
            .map(|n| FileEvent::Changed(PathBuf::from(format!("/{n}.rs"))))
            .collect::<Vec<_>>();
        enqueue_file_events(&mut pending, events);

        let first = take_file_event_batch(&mut pending, 2);
        let second = take_file_event_batch(&mut pending, 2);
        let third = take_file_event_batch(&mut pending, 2);

        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert_eq!(third.len(), 2);
        assert!(pending.is_empty());
        let ordered_paths = first
            .into_iter()
            .chain(second)
            .chain(third)
            .map(|event| match event {
                FileEvent::Changed(path) | FileEvent::Removed(path) => path,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ordered_paths,
            (0..6)
                .map(|n| PathBuf::from(format!("/{n}.rs")))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn retained_backlog_honors_default_batch_boundaries_and_large_bursts() {
        const BATCH: usize = 64;

        for total in [64usize, 65, 256, 257] {
            let mut pending = VecDeque::new();
            enqueue_file_events(
                &mut pending,
                (0..total).map(|n| FileEvent::Changed(PathBuf::from(format!("/{total}-{n}.rs")))),
            );

            let mut processed = Vec::new();
            while !pending.is_empty() {
                let batch = take_file_event_batch(&mut pending, BATCH);
                assert!(!batch.is_empty());
                assert!(batch.len() <= BATCH);
                processed.extend(batch);
            }

            assert_eq!(processed.len(), total);
            for (index, event) in processed.into_iter().enumerate() {
                let actual = match event {
                    FileEvent::Changed(path) | FileEvent::Removed(path) => path,
                };
                assert_eq!(actual, PathBuf::from(format!("/{total}-{index}.rs")));
            }
        }
    }

    #[test]
    fn retained_backlog_zero_batch_cannot_stall_forever() {
        let mut pending = VecDeque::from([FileEvent::Changed(PathBuf::from("/a.rs"))]);
        let batch = take_file_event_batch(&mut pending, 0);
        assert_eq!(batch.len(), 1);
        assert!(pending.is_empty());
    }

    #[test]
    fn retained_backlog_deduplicates_across_ticks_without_dropping_other_paths() {
        let mut pending = VecDeque::new();
        enqueue_file_events(
            &mut pending,
            [
                FileEvent::Changed(PathBuf::from("/a.rs")),
                FileEvent::Changed(PathBuf::from("/b.rs")),
                FileEvent::Changed(PathBuf::from("/c.rs")),
            ],
        );
        let first = take_file_event_batch(&mut pending, 1);
        assert!(matches!(&first[0], FileEvent::Changed(path) if path == &PathBuf::from("/a.rs")));

        enqueue_file_events(
            &mut pending,
            [
                FileEvent::Removed(PathBuf::from("/b.rs")),
                FileEvent::Changed(PathBuf::from("/d.rs")),
            ],
        );
        let rest = take_file_event_batch(&mut pending, 8);

        assert_eq!(rest.len(), 3);
        assert!(matches!(&rest[0], FileEvent::Changed(path) if path == &PathBuf::from("/c.rs")));
        assert!(matches!(&rest[1], FileEvent::Removed(path) if path == &PathBuf::from("/b.rs")));
        assert!(matches!(&rest[2], FileEvent::Changed(path) if path == &PathBuf::from("/d.rs")));
        assert!(pending.is_empty());
    }

    #[test]
    fn real_remove_supersedes_synthetic_changed_retry() {
        let path = PathBuf::from("/removed.rs");
        let mut pending = VecDeque::new();

        // Production enqueues synthetic retries first and real watcher events second.
        enqueue_file_events(&mut pending, [FileEvent::Changed(path.clone())]);
        enqueue_file_events(&mut pending, [FileEvent::Removed(path.clone())]);

        let batch = take_file_event_batch(&mut pending, 1);
        assert!(matches!(&batch[0], FileEvent::Removed(actual) if actual == &path));
        assert!(pending.is_empty());
    }

    /// A walk that cannot complete has no completion proof, so it has nothing
    /// to publish with. Authority must be untouched rather than advanced from
    /// whatever the partial walk happened to read.
    #[cfg(unix)]
    #[tokio::test]
    async fn incomplete_host_walk_publishes_no_workspace_authority() {
        use std::os::unix::net::UnixListener;

        let repo = tempfile::tempdir().unwrap();
        let tracked = repo.path().join("service.txt");
        std::fs::write(&tracked, b"regular while it is admitted\n").unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let state = Arc::new(DaemonState::open(init.layout).unwrap());
        sync_filesystem_with_graph(&state).await.unwrap();

        let tree_before = authority_tree(&state);
        assert!(tree_before
            .artifact_at_path(&test_repo_path("service.txt"))
            .is_some());

        std::fs::remove_file(&tracked).unwrap();
        let _listener = UnixListener::bind(&tracked).unwrap();

        let error = sync_filesystem_with_graph(&state).await.unwrap_err();
        assert!(
            error.to_string().contains("repository scan incomplete"),
            "{error}"
        );
        assert_eq!(
            authority_tree(&state),
            tree_before,
            "a walk that never completed must not move workspace authority"
        );
    }

    /// The mass-deletion guard refuses an observation, not a delta subset.
    /// Anything else the same unconfirmed walk saw must stay unpublished too.
    #[cfg(unix)]
    #[tokio::test]
    async fn unconfirmed_mass_deletion_publishes_no_part_of_the_observation() {
        let repo = tempfile::tempdir().unwrap();
        for index in 0..20 {
            std::fs::write(
                repo.path().join(format!("member{index}.txt")),
                format!("admitted {index}\n"),
            )
            .unwrap();
        }
        let init = kin_core::init(repo.path()).unwrap();
        let state = Arc::new(DaemonState::open(init.layout).unwrap());
        sync_filesystem_with_graph(&state).await.unwrap();

        let tree_before = authority_tree(&state);
        assert_eq!(tree_before.len(), 20);

        let survivor_entry_before = tree_before
            .artifact_at_path(&test_repo_path("member19.txt"))
            .unwrap()
            .entry;

        for index in 0..18 {
            std::fs::remove_file(repo.path().join(format!("member{index}.txt"))).unwrap();
        }
        // The same walk also carries an ordinary modification. It is a delta
        // the operator never refused, which is exactly why the old behavior
        // published it while suppressing the removals beside it.
        std::fs::write(
            repo.path().join("member19.txt"),
            b"edited in the same observation as the deletion\n",
        )
        .unwrap();

        let error = sync_filesystem_with_graph(&state).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("No part of an unconfirmed mass deletion is published"),
            "{error}"
        );
        assert!(state.is_mass_deletion_blocked());

        let tree_after = authority_tree(&state);
        assert_eq!(
            tree_after, tree_before,
            "no part of a refused observation may cross authority"
        );
        assert_eq!(
            tree_after
                .artifact_at_path(&test_repo_path("member19.txt"))
                .unwrap()
                .entry,
            survivor_entry_before,
            "the modification carried by a refused observation must not publish"
        );
        assert_eq!(
            tree_entry(&state, "member19.txt"),
            Some(survivor_entry_before),
            "graph state derived from a refused observation must not publish either"
        );
    }

    #[test]
    fn mass_deletion_guard_blocks_drastic_removals_only() {
        assert!(should_block_mass_deletion(80, 100, false)); // 80% gone -> blocked
        assert!(should_block_mass_deletion(100, 100, false)); // total wipe -> blocked
        assert!(!should_block_mass_deletion(75, 100, false)); // 25 survive (25*4==100): boundary, allowed
        assert!(!should_block_mass_deletion(40, 100, false)); // moderate deletion -> allowed
        assert!(!should_block_mass_deletion(0, 100, false)); // nothing removed -> allowed
        assert!(!should_block_mass_deletion(10, 10, false)); // tiny repo (baseline < 16) -> allowed
        assert!(!should_block_mass_deletion(100, 100, true)); // operator override -> allowed
    }

    #[test]
    fn retry_backoff_starts_at_the_poll_interval_and_doubles_to_a_ceiling() {
        let base = Duration::from_millis(100);
        assert_eq!(
            (1..=9)
                .map(|attempts| retry_backoff(attempts, base).as_millis())
                .collect::<Vec<_>>(),
            vec![100, 200, 400, 800, 1600, 3200, 6400, 6400, 6400],
            "the first retry waits one poll interval, later ones double to a ceiling"
        );
        assert_eq!(
            retry_backoff(u32::MAX, base),
            base * (1 << RETRY_BACKOFF_MAX_SHIFT),
            "an attempt count that cannot overflow the shift must still land on the ceiling"
        );
    }

    /// The reconcile pass as the disclosure surfaces see it.
    fn reconcile_report(
        supervisor: &crate::background_work::BackgroundWorkSupervisor,
        now: Instant,
    ) -> kin_cli::commands::resources::BackgroundPassReport {
        supervisor
            .reports(now)
            .into_iter()
            .find(|report| report.name == crate::background_work::PASS_RECONCILE)
            .expect("the reconcile pass is registered")
    }

    /// The tick decision this loop makes about its own state, exercised against
    /// a real ladder-waiting lane.
    ///
    /// The loop reports `set_deferred(retry_lane.deferred_owed(), tick_started)` and
    /// then finds `pending_events` empty, because a path waiting out its step is
    /// dropped from incoming events and its retry is not yet due. That
    /// combination used to report plain `idle` for the whole wait, so a ladder
    /// that never converged was indistinguishable from a quiet loop.
    #[test]
    fn a_ladder_waiting_tick_reports_waiting_deferred_rather_than_idle() {
        let base = Duration::from_millis(100);
        let start = Instant::now();
        let unstable = PathBuf::from("/repo/Cargo.lock");
        let mut lane = RetryLane::default();
        let supervisor = crate::background_work::BackgroundWorkSupervisor::default();
        let pass = supervisor.pass(crate::background_work::PASS_RECONCILE);

        // A quiet loop with an empty lane is genuinely idle.
        pass.set_deferred(lane.deferred_owed(), start);
        pass.idle();
        assert_eq!(reconcile_report(&supervisor, start).state, "idle");

        // Defer the path, then advance to the middle of its ladder step. This is
        // the state the livelock sits in.
        lane.defer(&unstable, start, base);
        let mid_wait = start + base / 2;
        assert!(
            lane.waiting(&unstable, mid_wait),
            "the path must still be waiting out its step for this to be the case under test"
        );
        assert!(
            lane.take_due(mid_wait).is_empty(),
            "no retry is due yet, so the tick observes an empty event queue"
        );

        // The tick the loop actually runs: report the lane, then find nothing to
        // admit and end the working stretch.
        pass.set_deferred(lane.deferred_owed(), mid_wait);
        pass.idle();

        let report = reconcile_report(&supervisor, mid_wait + Duration::from_secs(4_021));
        assert_eq!(
            report.state, "waiting_deferred",
            "work is owed, so this tick is not idle"
        );
        assert_eq!(report.deferred_seconds, Some(4_021));
        assert_eq!(report.working_seconds, None);
    }

    /// The other direction. Once the path settles and the lane drains, the same
    /// decision reports true idle, so the state cannot be a constant.
    #[test]
    fn a_settled_path_returns_the_tick_to_idle() {
        let base = Duration::from_millis(100);
        let start = Instant::now();
        let unstable = PathBuf::from("/repo/Cargo.lock");
        let mut lane = RetryLane::default();
        let supervisor = crate::background_work::BackgroundWorkSupervisor::default();
        let pass = supervisor.pass(crate::background_work::PASS_RECONCILE);

        lane.defer(&unstable, start, base);
        pass.set_deferred(lane.deferred_owed(), start);
        pass.idle();
        assert_eq!(
            reconcile_report(&supervisor, start).state,
            "waiting_deferred"
        );

        lane.forget(&unstable);
        pass.set_deferred(lane.deferred_owed(), start + base);
        pass.idle();
        assert_eq!(reconcile_report(&supervisor, start + base).state, "idle");
    }

    /// The clock has to survive the tick that collects a due retry, which is the
    /// tick a spinning loop runs most often.
    ///
    /// `take_due` empties the queue every time a ladder step elapses, so keying
    /// the clock on the queue would clear it on each due tick and restart it on
    /// the re-deferral. The reported age would then never exceed one backoff
    /// step, and a loop churning for over an hour would report a few seconds.
    #[test]
    fn the_deferred_clock_survives_a_due_retry_and_re_deferral() {
        let base = Duration::from_millis(100);
        let start = Instant::now();
        let unstable = PathBuf::from("/repo/Cargo.lock");
        let mut lane = RetryLane::default();
        let supervisor = crate::background_work::BackgroundWorkSupervisor::default();
        let pass = supervisor.pass(crate::background_work::PASS_RECONCILE);

        lane.defer(&unstable, start, base);
        pass.set_deferred(lane.deferred_owed(), start);

        // Five full cycles of "step elapses, retry is collected, path defers
        // again" — the shape of a path being rewritten faster than it reconciles.
        // Advance past the backoff ceiling each cycle so every step has genuinely
        // elapsed however far the ladder has widened.
        let past_ceiling = base * (1 << RETRY_BACKOFF_MAX_SHIFT) * 2;
        let mut now = start;
        for _ in 0..5 {
            now += past_ceiling;
            assert_eq!(
                lane.take_due(now),
                vec![unstable.clone()],
                "the elapsed step hands the path back"
            );
            assert!(
                lane.is_empty(),
                "the queue is empty at exactly this moment, which is the trap"
            );
            assert!(
                lane.deferred_owed(),
                "the path is still unstable, so the clock must not clear here"
            );
            pass.set_deferred(lane.deferred_owed(), now);
            lane.defer(&unstable, now, base);
        }

        let report = reconcile_report(&supervisor, now);
        assert_eq!(report.state, "waiting_deferred");
        assert_eq!(
            report.deferred_seconds,
            Some(now.saturating_duration_since(start).as_secs()),
            "the age spans every cycle, not just the last one"
        );
    }

    #[test]
    fn retry_lane_holds_an_unstable_path_and_releases_it_when_its_step_elapses() {
        let base = Duration::from_millis(100);
        let start = Instant::now();
        let unstable = PathBuf::from("/repo/Cargo.lock");
        let healthy = PathBuf::from("/repo/src/lib.rs");
        let mut lane = RetryLane::default();

        let first = lane.defer(&unstable, start, base);
        assert_eq!(
            first,
            Deferral {
                attempts: 1,
                wait: base
            }
        );
        assert!(lane.waiting(&unstable, start));
        assert!(lane.waiting(&unstable, start + base - Duration::from_millis(1)));
        assert!(!lane.waiting(&unstable, start + base));
        assert!(
            !lane.waiting(&healthy, start),
            "a path with no ladder is never held back"
        );
        assert!(
            lane.take_due(start).is_empty(),
            "a path inside its ladder step is not due"
        );
        assert_eq!(lane.take_due(start + base), vec![unstable.clone()]);

        // Deferring again keeps climbing rather than restarting the ladder.
        let second = lane.defer(&unstable, start + base, base);
        assert_eq!(
            second,
            Deferral {
                attempts: 2,
                wait: base * 2
            }
        );
        assert!(lane.waiting(&unstable, start + base * 2));
        assert!(!lane.waiting(&unstable, start + base * 3));
    }

    #[test]
    fn retry_lane_forgets_the_ladder_of_a_path_that_reconciles() {
        let base = Duration::from_millis(100);
        let start = Instant::now();
        let path = PathBuf::from("/repo/Cargo.lock");
        let mut lane = RetryLane::default();

        for _ in 0..4 {
            lane.defer(&path, start, base);
        }
        assert!(!lane.is_empty());

        // One tick that looked at the path without deferring it.
        lane.forget(&path);
        assert!(lane.is_empty());
        assert!(!lane.waiting(&path, start));
        assert_eq!(
            lane.defer(&path, start, base),
            Deferral {
                attempts: 1,
                wait: base
            },
            "a path that settled must not inherit the wait it earned while flapping"
        );
    }

    /// The livelock, counted. A path rewritten faster than it reconciles defers
    /// on every attempt, and each attempt costs a complete exact-tree admission.
    /// The pre-fix loop re-injected it on the very next turn, so the number of
    /// admissions over a window was the number of turns the window allowed. The
    /// ladder makes that count logarithmic in the window instead.
    ///
    /// Simulated time throughout: the counts are exact, not sampled.
    #[test]
    fn an_unstable_path_costs_a_bounded_number_of_admissions_where_the_old_loop_spun() {
        let base = Duration::from_millis(100);
        // Each attempt runs a complete workspace scan. 50ms is a small store; the
        // founder's umbrella took far longer, which only widens the gap below.
        let admission_cost = Duration::from_millis(50);
        let window = Duration::from_secs(60);
        let path = PathBuf::from("/repo/Cargo.lock");

        // Pre-fix: the retry queue was drained into the tick unconditionally, so
        // the loop attempted the path again the moment the previous attempt ended.
        let mut spinning_attempts = 0u32;
        let mut elapsed = Duration::ZERO;
        while elapsed < window {
            spinning_attempts += 1;
            elapsed += admission_cost;
        }

        // Post-fix: the same always-deferring path, but the lane decides when it
        // is eligible. The loop otherwise polls, which costs no admission.
        let start = Instant::now();
        let mut lane = RetryLane::default();
        let mut ladder_attempts = 0u32;
        let mut now = start;
        lane.defer(&path, now, base);
        while now < start + window {
            let due = lane.take_due(now);
            if due.is_empty() {
                now += base;
                continue;
            }
            ladder_attempts += 1;
            now += admission_cost;
            lane.defer(&path, now, base);
        }

        assert_eq!(
            spinning_attempts, 1200,
            "the pre-fix loop attempted the path once per admission for the whole window"
        );
        assert!(
            ladder_attempts <= 20,
            "a permanently unstable path must cost a bounded number of admissions per \
             minute, got {ladder_attempts}"
        );
        assert!(
            ladder_attempts >= 2,
            "the ladder must keep retrying rather than abandoning the path, got \
             {ladder_attempts}"
        );
        assert!(
            spinning_attempts / ladder_attempts >= 50,
            "the ladder must be at least an order of magnitude cheaper: {spinning_attempts} \
             vs {ladder_attempts}"
        );
    }

    /// Two-sided: a path that reconciles is never held back. The same simulation
    /// with a path that stops deferring after its first attempt spends nothing on
    /// the ladder and is looked at the moment its event arrives.
    #[test]
    fn a_progressing_path_is_never_held_back_by_the_ladder() {
        let base = Duration::from_millis(100);
        let start = Instant::now();
        let path = PathBuf::from("/repo/src/lib.rs");
        let mut lane = RetryLane::default();

        for tick in 0..100u32 {
            let now = start + base * tick;
            assert!(
                !lane.waiting(&path, now),
                "a path that keeps reconciling must never wait on a ladder step"
            );
            // The tick looked at it and admitted it, so nothing is deferred.
            lane.forget(&path);
            assert!(lane.is_empty());
        }
    }

    #[test]
    fn only_the_mid_read_race_earns_a_retry() {
        assert!(reconcile_error_earns_retry(
            &kin_reconcile::ReconcileError::FileModifiedDuringReconcile {
                path: "src/lib.rs".to_string(),
                expected_hash: "aa".to_string(),
                actual_hash: "bb".to_string(),
            }
        ));
        assert!(!reconcile_error_earns_retry(
            &kin_reconcile::ReconcileError::TrafficCheck("unrelated failure".to_string())
        ));
        assert!(!reconcile_error_earns_retry(
            &kin_reconcile::ReconcileError::BrokenAstRejected {
                file_id: FilePathId::new("src/lib.rs"),
                error_ranges: Vec::new(),
            }
        ));
    }

    /// The silence that let this burn a core for hours: the mid-read race
    /// re-queued at debug while the daemon ran at info. A repeat has to escalate,
    /// and a single benign save must not.
    #[test]
    fn a_repeat_deferral_escalates_from_debug_to_warn() {
        use std::sync::Mutex;
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Default)]
        struct Captured {
            events: Vec<(tracing::Level, String)>,
        }

        struct CaptureLayer(Arc<Mutex<Captured>>);

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct Render<'a>(&'a mut String);
                impl tracing::field::Visit for Render<'_> {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        use std::fmt::Write;
                        let _ = write!(self.0, "{}={:?} ", field.name(), value);
                    }
                }
                let mut rendered = String::new();
                event.record(&mut Render(&mut rendered));
                self.0
                    .lock()
                    .unwrap()
                    .events
                    .push((*event.metadata().level(), rendered));
            }
        }

        let captured = Arc::new(Mutex::new(Captured::default()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer(Arc::clone(&captured)));
        let error = kin_reconcile::ReconcileError::FileModifiedDuringReconcile {
            path: "Cargo.lock".to_string(),
            expected_hash: "aa".to_string(),
            actual_hash: "bb".to_string(),
        };
        let path = PathBuf::from("/repo/Cargo.lock");

        {
            let _capture = crate::capture_events_on_this_thread(subscriber);
            for attempts in 1..=4u32 {
                report_modified_during_reconcile(
                    &path,
                    &error,
                    Deferral {
                        attempts,
                        wait: retry_backoff(attempts, Duration::from_millis(100)),
                    },
                );
            }
        }

        let events = std::mem::take(&mut captured.lock().unwrap().events);
        let levels = events.iter().map(|(level, _)| *level).collect::<Vec<_>>();
        assert_eq!(
            levels,
            vec![
                tracing::Level::DEBUG,
                tracing::Level::DEBUG,
                tracing::Level::WARN,
                tracing::Level::WARN,
            ],
            "a routine save stays at debug and a repeat escalates at {RETRY_WARN_ATTEMPTS} \
             attempts; captured {events:?}"
        );
        assert!(
            events[2].1.contains("attempts=3") && events[2].1.contains("backoff_ms=400"),
            "the escalated line must carry the attempt count and the wait: {:?}",
            events[2].1
        );
    }

    /// Which of the loop's deferral sites the live spin used, proven rather than
    /// inferred from the log's silence. A file replaced by rename between the
    /// reconciler's index read and its verify read is the mid-read race, and the
    /// rename keeps every read a complete, parseable file so a torn read cannot
    /// stand in for the race being tested.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_file_replaced_under_the_reconciler_reports_the_mid_read_race() {
        use std::sync::atomic::AtomicBool;

        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        let path = repo.path().join("src/lib.rs");
        let first = wide_source("first");
        let second = wide_source("second");
        std::fs::write(&path, &first).unwrap();

        let state = open_test_state(&repo);
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let stop = Arc::clone(&stop);
            let path = path.clone();
            let staging = repo.path().join("src/.lib.rs.staged");
            let first = first.clone();
            let second = second.clone();
            std::thread::spawn(move || {
                let mut flip = false;
                while !stop.load(Ordering::Relaxed) {
                    let body = if flip { &first } else { &second };
                    flip = !flip;
                    if std::fs::write(&staging, body).is_ok() {
                        let _ = std::fs::rename(&staging, &path);
                    }
                }
            })
        };

        let mut reconciler = state.reconciler.write().await;
        let mut observed = None;
        let mut other_outcomes = Vec::new();
        for _ in 0..200 {
            match reconciler.reconcile_file_change(
                &FileEvent::Changed(path.clone()),
                &state.blobs,
                state.graph.as_ref(),
            ) {
                Err(error) if reconcile_error_earns_retry(&error) => {
                    observed = Some(error);
                    break;
                }
                Err(error) => other_outcomes.push(format!("{error}")),
                Ok(result) => other_outcomes.push(format!("{:?}", result.outcome)),
            }
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();

        let observed = observed.unwrap_or_else(|| {
            panic!(
                "a file replaced under the reconciler must report the mid-read race; \
                 saw instead: {other_outcomes:?}"
            )
        });
        assert!(
            matches!(
                observed,
                kin_reconcile::ReconcileError::FileModifiedDuringReconcile { .. }
            ),
            "the deferral the live spin took is the mid-read race, not one of the four \
             warn-level sites: {observed:?}"
        );
    }

    /// Two-sided acceptance against the real loop: a file rewritten in a tight
    /// loop must still reach graph truth once it settles. The ladder slows an
    /// unstable path; it must not lose it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_file_rewritten_in_a_tight_loop_still_reaches_graph_truth() {
        use std::sync::atomic::AtomicBool;

        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("src")).unwrap();
        let path = repo.path().join("src/lib.rs");
        std::fs::write(&path, b"pub fn start() {}\n").unwrap();

        let state = open_test_state(&repo);
        // Ambient watcher observation revises tracked members and never enlarges
        // the workspace, so the path has to cross the explicit admission seam
        // before the loop can reconcile edits to it at all.
        sync_filesystem_with_graph(&state).await.unwrap();
        assert!(
            tree_entry(&state, "src/lib.rs").is_some(),
            "the fixture must be tracked before the loop is asked to revise it"
        );

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let loop_state = Arc::clone(&state);
        let runner = tokio::spawn(async move {
            run_loop(
                loop_state,
                LoopConfig {
                    poll_interval_ms: 10,
                    batch_size: 64,
                },
                cancel_rx,
            )
            .await
        });

        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let stop = Arc::clone(&stop);
            let path = path.clone();
            std::thread::spawn(move || {
                let mut revision = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    revision += 1;
                    let _ = std::fs::write(
                        &path,
                        format!("pub fn revision_{revision}() -> u32 {{ {revision} }}\n"),
                    );
                }
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();

        let settled = b"pub fn settled() -> u32 { 0 }\n";
        std::fs::write(&path, settled).unwrap();

        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last = None;
        while Instant::now() < deadline {
            if let Some(entry) = tree_entry(&state, "src/lib.rs") {
                let bytes = read_tree_entry_bytes(&state, entry);
                if bytes == settled {
                    last = Some(bytes);
                    break;
                }
                last = Some(bytes);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        cancel_tx.send(true).unwrap();
        runner.await.unwrap().unwrap();

        assert_eq!(
            last.as_deref(),
            Some(settled.as_slice()),
            "a path slowed by the retry ladder must still reach graph truth once it settles"
        );
        let pass = state
            .background_work
            .registered(crate::background_work::PASS_RECONCILE)
            .expect("the reconcile loop must register with the background-work supervisor");
        assert!(
            pass.progress() > 0,
            "the supervisor must observe the reconcile pass admitting work"
        );
    }

    fn entity_ids_for(state: &DaemonState, file: &str) -> Vec<EntityId> {
        let mut ids = state
            .graph
            .query_entities(&EntityFilter {
                file_path: Some(FilePathId::new(file)),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }

    /// Deleting a source file takes its entities with it.
    ///
    /// Entity removal is an explicit transition rather than something a tree
    /// change implies, so an admission that dropped the artifact and left the
    /// entities behind was refused outright: authority had already committed
    /// the removal, the graph kept the old tree, and the watcher retried that
    /// path for as long as the daemon ran.
    #[tokio::test]
    async fn deleting_an_entity_bearing_file_removes_its_entities_with_the_artifact() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let root = state.layout.working_dir().to_path_buf();
        std::fs::write(root.join("gone.rs"), b"pub fn gone() -> u32 { 3 }\n").unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        let ids = entity_ids_for(&state, "gone.rs");
        assert!(
            !ids.is_empty(),
            "the fixture admitted no entities, so nothing below proves an eviction"
        );

        std::fs::remove_file(root.join("gone.rs")).unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        assert!(tree_entry(&state, "gone.rs").is_none());
        assert!(entity_ids_for(&state, "gone.rs").is_empty());
        for id in &ids {
            assert!(
                state.graph.get_entity(id).unwrap().is_none(),
                "a deleted file's entity id still resolves: {id}"
            );
        }
        assert_eq!(
            authority_tree(&state).artifact_at_path(&test_repo_path("gone.rs")),
            None,
            "graph truth and repository authority disagree about the removal"
        );
    }

    /// A rule written after admission retracts what it names.
    ///
    /// Listing a path in `.kinignore` is a statement about the semantic index,
    /// not only about future walks. The next admission therefore has to remove
    /// the artifact and every entity, layout, and enrichment facet that let it
    /// rank, while the file itself stays on disk.
    #[tokio::test]
    async fn a_rule_added_after_admission_retracts_the_path_and_its_entities() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let root = state.layout.working_dir().to_path_buf();

        std::fs::create_dir_all(root.join("investor/deck")).unwrap();
        std::fs::write(
            root.join("investor/deck/build_deck.rs"),
            b"pub fn valuation_slide() -> u32 { 7 }\n",
        )
        .unwrap();
        std::fs::write(root.join("keep.rs"), b"pub fn kept() -> u32 { 1 }\n").unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        let private_entities = entity_ids_for(&state, "investor/deck/build_deck.rs");
        let kept_entities = entity_ids_for(&state, "keep.rs");
        assert!(
            !private_entities.is_empty(),
            "the fixture admitted no entities, so nothing below proves an eviction"
        );
        assert!(!kept_entities.is_empty());

        std::fs::write(root.join(".kinignore"), b"investor\n").unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        assert!(
            tree_entry(&state, "investor/deck/build_deck.rs").is_none(),
            "a newly ignored path is still tracked"
        );
        assert!(
            entity_ids_for(&state, "investor/deck/build_deck.rs").is_empty(),
            "a retracted path still owns entities"
        );
        for id in &private_entities {
            assert!(
                state.graph.get_entity(id).unwrap().is_none(),
                "a retracted entity id still resolves: {id}"
            );
        }
        assert!(!state
            .graph
            .entity_bearing_file_paths()
            .contains(&"investor/deck/build_deck.rs".to_string()));
        assert!(
            root.join("investor/deck/build_deck.rs").exists(),
            "retraction untracks a path; it must never delete the file"
        );

        // The two-sided arm: an unnamed sibling keeps its artifact and the
        // exact entity ids it had, so the rule retracted one path rather than
        // resetting the graph.
        assert!(tree_entry(&state, "keep.rs").is_some());
        assert_eq!(entity_ids_for(&state, "keep.rs"), kept_entities);
    }

    /// Establish a repository whose graph-owned admission policy excludes
    /// `.claude/`, the way every real one does: the rule file is tracked before
    /// the excluded content exists.
    ///
    /// A repository imported from Git resolves its policy from the `.gitignore`
    /// blobs the import carried, so the rules are in force before the daemon's
    /// first ambient pass. This fixture reproduces that state rather than
    /// asserting anything about it.
    async fn repository_with_policy_excluding_claude(root: &Path, state: &DaemonState) {
        std::fs::write(root.join(".gitignore"), b".claude/\n").unwrap();
        std::fs::write(root.join("keep.rs"), b"pub fn kept() -> u32 { 1 }\n").unwrap();
        sync_filesystem_with_graph(state).await.unwrap();
        assert!(
            tree_entry(state, ".gitignore").is_some(),
            "the fixture never admitted its own rule file, so no policy is in force"
        );
    }

    /// A dirty subtree the graph-owned policy excludes admits the rest of the
    /// tree instead of failing the whole admission.
    ///
    /// The scanner reads `.kinignore` and its built-in defaults; the durable
    /// admission policy is compiled from every `.gitignore` and `.kinignore`
    /// blob in the tree plus the frozen local overlay. A path only the second
    /// one excludes was proposed by the walk and refused at the authority
    /// boundary, and that refusal fails the entire exact-tree admission, so one
    /// churning agent lock file left every other file in the working copy
    /// unadmitted and the store answered from nothing (FIR-2346).
    ///
    /// The nested checkout under the excluded directory is the shape that
    /// produced it on the founder's machine: a git worktree whose `.git` file
    /// is control metadata while everything beside it is ordinary content.
    #[tokio::test]
    async fn a_dirty_policy_excluded_subtree_admits_the_rest_of_the_tree() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let root = state.layout.working_dir().to_path_buf();
        repository_with_policy_excluding_claude(&root, &state).await;

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), b"pub fn library() -> u32 { 2 }\n").unwrap();
        std::fs::create_dir_all(root.join(".claude/worktrees/lane-a/src")).unwrap();
        std::fs::write(root.join(".claude/scheduled_tasks.lock"), b"held\n").unwrap();
        std::fs::write(
            root.join(".claude/worktrees/lane-a/.git"),
            b"gitdir: ../../../.git/worktrees/lane-a\n",
        )
        .unwrap();
        std::fs::write(
            root.join(".claude/worktrees/lane-a/src/dirty.rs"),
            b"pub fn dirty() -> u32 { 3 }\n",
        )
        .unwrap();

        // The pass completing at all is what proves nothing was deferred: a
        // deferral is only reachable from the failure arm this admission used
        // to take, where the loop defers every path in the batch and admits
        // none of them.
        sync_filesystem_with_graph(&state).await.unwrap();

        assert!(
            tree_entry(&state, "src/lib.rs").is_some(),
            "an excluded subtree left an ordinary file unadmitted"
        );
        assert!(
            !entity_ids_for(&state, "src/lib.rs").is_empty(),
            "the pass admitted a tree it derived no semantics from, which is no progress"
        );
        assert!(
            tree_entry(&state, "keep.rs").is_some(),
            "the file admitted before the excluded subtree appeared was dropped"
        );
        assert!(tree_entry(&state, ".gitignore").is_some());
        assert!(
            tree_entry(&state, ".claude/scheduled_tasks.lock").is_none(),
            "a policy-excluded path reached repository truth"
        );
        assert!(tree_entry(&state, ".claude/worktrees/lane-a/src/dirty.rs").is_none());

        // The walk declined to observe them rather than silently finding
        // nothing, and it says how many. An operator reading a missing file
        // gets an answer instead of a quiet tree.
        let excluded = state
            .background_work
            .reconcile()
            .report(Instant::now())
            .policy_excluded_path_count;
        assert!(
            excluded > 0,
            "the pass skipped policy-excluded content without disclosing any of it"
        );
    }

    /// Churn under an excluded path is not work, and the loop must not spend a
    /// working stretch on it.
    ///
    /// Every excluded notification used to schedule a complete working-copy
    /// admission that could only conclude there was nothing to admit, which is
    /// a working stretch that records no progress. Ten minutes of that is what
    /// the supervisor parks a pass for, and it parked the founder's store at
    /// zero entities while the loop was doing exactly what it should.
    #[tokio::test]
    async fn continuous_excluded_churn_never_reaches_the_admission_path() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let root = state.layout.working_dir().to_path_buf();
        repository_with_policy_excluding_claude(&root, &state).await;

        let (_, policy) = current_authority_admission(&state).unwrap();
        let policy = policy.expect("a local workspace resolves an admission policy");
        std::fs::create_dir_all(root.join(".claude/worktrees/lane-a")).unwrap();
        std::fs::write(root.join(".claude/scheduled_tasks.lock"), b"held\n").unwrap();
        std::fs::write(root.join("src.rs"), b"pub fn src() -> u32 { 4 }\n").unwrap();

        let excluded = FileEvent::Changed(root.join(".claude/scheduled_tasks.lock"));
        assert!(
            event_is_policy_excluded(&state, Some(&policy), &excluded),
            "a churning excluded path still schedules a complete admission"
        );
        assert!(event_is_policy_excluded(
            &state,
            Some(&policy),
            &FileEvent::Changed(root.join(".claude/worktrees/lane-a/head")),
        ));

        // Two-sided, or the predicate could be "drop everything". Ordinary
        // content still reaches the admission path, and so does a tracked path
        // even when the rules would exclude it today.
        assert!(!event_is_policy_excluded(
            &state,
            Some(&policy),
            &FileEvent::Changed(root.join("src.rs")),
        ));
        assert!(!event_is_policy_excluded(
            &state,
            Some(&policy),
            &FileEvent::Changed(root.join("keep.rs")),
        ));
        // Before the first pass of a daemon's life there is no resolved policy,
        // and nothing may be dropped on the strength of not having one.
        assert!(!event_is_policy_excluded(&state, None, &excluded));
    }

    /// A pass making real progress is never stalled by excluded churn beside
    /// it.
    ///
    /// The supervisor's verdict is the half that decides whether the store
    /// survives, so it is exercised directly rather than inferred from the
    /// filter above: excluded notifications arrive continuously for well past
    /// the stall threshold while the loop keeps admitting, and the sweep must
    /// leave the pass running.
    #[test]
    fn excluded_churn_beside_real_progress_never_parks_the_pass() {
        let supervisor =
            crate::background_work::BackgroundWorkSupervisor::new(Duration::from_secs(600));
        let pass = supervisor.pass(crate::background_work::PASS_RECONCILE);
        let start = Instant::now();

        // Twenty minutes of ticks. Each one admits something real while
        // excluded paths churn beside it, which is the working copy of anyone
        // running an agent in their repository.
        let mut now = start;
        for tick in 0..120 {
            now = start + Duration::from_secs(tick * 10);
            pass.working(now);
            pass.advanced(1, now);
            assert!(
                supervisor.sweep(now).is_empty(),
                "a pass that is admitting was parked at tick {tick}"
            );
        }
        assert!(!pass.halted());
        assert!(supervisor.reconcile_report(now).parked.is_none());

        // The other side: with the same clock and no progress, the sweep does
        // stop it. Without this the assertions above would hold for a
        // supervisor that never parks anything.
        let starved =
            crate::background_work::BackgroundWorkSupervisor::new(Duration::from_secs(600));
        let starved_pass = starved.pass(crate::background_work::PASS_RECONCILE);
        starved_pass.working(start);
        assert!(starved.sweep(start + Duration::from_secs(1_200)).len() == 1);
        assert!(starved_pass.halted());
    }

    /// The park names its own cause wherever the status string appears.
    ///
    /// `parked-by-supervisor` was the whole account a surface gave, and the
    /// reason lived only in a log line from whenever it happened. The
    /// supervisor already held the reason and the readings behind it.
    #[test]
    fn a_parked_reconcile_pass_publishes_its_reason_and_its_counts() {
        let supervisor =
            crate::background_work::BackgroundWorkSupervisor::new(Duration::from_secs(600));
        let pass = supervisor.pass(crate::background_work::PASS_RECONCILE);
        let start = Instant::now();
        pass.working(start);
        pass.advanced(3, start);
        pass.set_deferred(true, start);
        let stopped = supervisor.sweep(start + Duration::from_secs(1_050));
        assert_eq!(stopped.len(), 1);

        let report = supervisor.reconcile_report(start + Duration::from_secs(1_050));
        let parked = report
            .parked
            .clone()
            .expect("a parked pass reports its park");
        assert!(parked.reason.contains("without recording any progress"));
        assert_eq!(parked.progress, 3);
        assert_eq!(parked.stall_threshold_seconds, 600);
        assert_eq!(parked.progress_age_seconds, Some(1_050));
        assert_eq!(parked.deferred_seconds, Some(1_050));
        assert!(
            report
                .degraded_reasons()
                .iter()
                .any(|reason| reason.contains("parked by the background-work supervisor")),
            "a parked loop reported no degraded reason: {:?}",
            report.degraded_reasons()
        );

        // It serializes, because every surface that carries it is JSON, and it
        // stays absent on a healthy loop rather than serializing an empty park.
        let encoded = serde_json::to_value(&report).unwrap();
        assert_eq!(encoded["parked"]["progress"], 3);
        assert_eq!(encoded["parked"]["stall_threshold_seconds"], 600);
        assert!(encoded["parked"]["reason"]
            .as_str()
            .unwrap()
            .contains("was stopped"));
        let decoded: kin_cli::commands::resources::ReconcileHealth =
            serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.parked, report.parked);

        let healthy =
            crate::background_work::BackgroundWorkSupervisor::new(Duration::from_secs(600));
        healthy.pass(crate::background_work::PASS_RECONCILE);
        let healthy_report = healthy.reconcile_report(start);
        assert!(healthy_report.parked.is_none());
        assert!(serde_json::to_value(&healthy_report).unwrap()["parked"].is_null());
    }

    /// A rule wide enough to empty the repository is refused, not obeyed.
    ///
    /// Retraction is automatic now, so a careless rule reaches graph truth
    /// without anyone confirming it. The mass-deletion guard is what stands
    /// between a mistyped `.kinignore` and a wiped graph, and it has to count
    /// retractions the same way it counts deletions.
    #[tokio::test]
    async fn a_retraction_wide_enough_to_be_a_wipe_is_refused() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let root = state.layout.working_dir().to_path_buf();
        std::fs::create_dir_all(root.join("bulk")).unwrap();
        for index in 0..20 {
            std::fs::write(
                root.join(format!("bulk/member{index}.rs")),
                format!("pub fn member_{index}() -> u32 {{ {index} }}\n"),
            )
            .unwrap();
        }
        sync_filesystem_with_graph(&state).await.unwrap();

        let before = state.graph.resolved_tree();
        assert_eq!(before.len(), 20, "the guard needs a non-trivial tree");

        std::fs::write(root.join(".kinignore"), b"bulk\n").unwrap();
        let error = sync_filesystem_with_graph(&state)
            .await
            .expect_err("a rule covering the whole repository must be refused");
        assert!(
            error.to_string().contains("unconfirmed mass deletion"),
            "{error}"
        );
        assert_eq!(
            state.graph.resolved_tree(),
            before,
            "a refused observation must retain graph truth whole"
        );
        assert!(
            !entity_ids_for(&state, "bulk/member0.rs").is_empty(),
            "a refused retraction must not have evicted anything"
        );
    }

    fn entity_names_for(state: &DaemonState, file: &str) -> Vec<String> {
        let mut names = state
            .graph
            .query_entities(&EntityFilter {
                file_path: Some(FilePathId::new(file)),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|entity| entity.name)
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    /// An edit reaches the graph even when the file declares one name twice.
    ///
    /// Entity identity is derived from the declaration's start line, so an edit
    /// above a declaration invalidates the identity the graph holds for it.
    /// Re-matching then falls back to name and kind, and a file carrying a
    /// cfg-gated pair collapsed both parsed halves onto whichever half the graph
    /// returned first. Two deltas for one entity is not a transaction, so the
    /// whole reconcile was refused and the edit never became queryable.
    #[tokio::test]
    async fn an_edit_above_a_duplicated_declaration_admits_the_new_entity() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let root = state.layout.working_dir().to_path_buf();
        std::fs::write(
            root.join("hooks.rs"),
            b"#[cfg(unix)]\npub fn hook() -> u32 { 1 }\n\n#[cfg(not(unix))]\npub fn hook() -> u32 { 2 }\n",
        )
        .unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();
        assert_eq!(
            entity_names_for(&state, "hooks.rs"),
            vec!["hook".to_string(), "hook".to_string()],
            "the fixture needs both halves of the duplicated declaration admitted"
        );

        std::fs::write(
            root.join("hooks.rs"),
            b"pub fn probe() -> u32 { 9 }\n\n#[cfg(unix)]\npub fn hook() -> u32 { 1 }\n\n#[cfg(not(unix))]\npub fn hook() -> u32 { 2 }\n",
        )
        .unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        assert!(
            entity_names_for(&state, "hooks.rs").contains(&"probe".to_string()),
            "a function added by an ordinary edit never became queryable: {:?}",
            entity_names_for(&state, "hooks.rs")
        );
        assert_eq!(
            entity_names_for(&state, "hooks.rs"),
            vec!["hook".to_string(), "hook".to_string(), "probe".to_string()],
            "the edit must leave one entity per declaration"
        );
    }

    /// A comment-only edit advances the same file's entities.
    ///
    /// Every entity in an edited file carries the file's blob hash, so a comment
    /// is a real modification of each of them. The pass therefore has to hold the
    /// one-delta-per-entity invariant on an edit that changes no declaration at
    /// all, and it must keep the entity ids it already published.
    #[tokio::test]
    async fn a_comment_only_edit_keeps_the_files_entities_and_their_ids() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let root = state.layout.working_dir().to_path_buf();
        std::fs::write(
            root.join("notes.rs"),
            b"// leading note\n#[cfg(unix)]\npub fn note() -> u32 { 1 }\n\n#[cfg(not(unix))]\npub fn note() -> u32 { 2 }\n",
        )
        .unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();
        let before = entity_ids_for(&state, "notes.rs");
        assert_eq!(before.len(), 2, "the fixture needs both declarations");

        std::fs::write(
            root.join("notes.rs"),
            b"// leading note\n#[cfg(unix)]\npub fn note() -> u32 { 1 }\n\n#[cfg(not(unix))]\npub fn note() -> u32 { 2 }\n\n// trailing note\n",
        )
        .unwrap();
        sync_filesystem_with_graph(&state).await.unwrap();

        assert_eq!(
            entity_ids_for(&state, "notes.rs"),
            before,
            "a comment-only edit must leave every declaration's identity alone"
        );
    }

    /// A file wide enough that indexing it takes long enough for a replacement to
    /// land between the reconciler's two reads.
    ///
    /// Gated with its only caller: a helper whose call site is platform-gated is
    /// dead code on every other platform, and no macOS build can see that.
    #[cfg(unix)]
    fn wide_source(tag: &str) -> Vec<u8> {
        let mut source = String::new();
        for index in 0..4000 {
            source.push_str(&format!(
                "pub fn {tag}_item_{index}(value: u32) -> u32 {{ value + {index} }}\n"
            ));
        }
        source.into_bytes()
    }

    /// The ambient tick with nothing else in the daemon publishes exactly as it
    /// did before it learned to stand down. Its mode is the only thing that
    /// changed, and a mode that skipped a publication on a quiet daemon would
    /// leave every observed write outside repository authority.
    #[test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    fn an_ambient_tick_with_no_commit_in_flight_publishes_its_own_successor() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            repo.path().join("quiet.rs"),
            b"pub fn quiet() -> u32 { 1 }\n",
        )
        .unwrap();
        let repo_path = test_repo_path("quiet.rs");
        let observation = std::iter::once(repo_path.clone()).collect::<BTreeSet<_>>();

        let before = authority_generation(&state);
        let admission = exact_tree_admission(
            &state,
            Some(&observation),
            TreePublication::StandaloneUnlessACommitIsWaiting,
        )
        .unwrap();

        assert!(
            !admission.yielded_to_pending_commit,
            "there is no commit to stand down for"
        );
        assert!(
            !admission.deltas.is_empty(),
            "the observed write must be admitted"
        );
        assert_eq!(
            authority_generation(&state) - before,
            1,
            "a tick with no commit in flight publishes exactly one successor"
        );
        assert!(
            state
                .graph
                .resolved_tree()
                .artifact_at_path(&repo_path)
                .is_some(),
            "the derived graph carries the admitted path"
        );
    }

    /// The racing shape, decided the way it is decided in the daemon: the tick
    /// reaches its publication while a commit is inside the daemon, and stands
    /// down.
    ///
    /// What it must leave behind is a pass that never happened. Publishing is
    /// the cost being avoided, so the generation must not move; but a tick that
    /// skipped only the publication and still applied its transition would leave
    /// the derived graph carrying a tree repository authority never accepted,
    /// and every later admission plans out of that tree and is refused against
    /// the older one. So the graph must not carry the path either.
    #[test]
    // Commit phases are emitted at debug level when they are fast, and the
    // level a `tracing` event is filtered by is a process-global hint. A test
    // that captures those events therefore cannot run beside one that emits
    // them, so every test on either side of that shares this group.
    #[serial_test::serial(commit_phase_capture)]
    fn a_tick_that_meets_a_commit_at_its_publication_publishes_nothing() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            repo.path().join("raced.rs"),
            b"pub fn raced() -> u32 { 1 }\n",
        )
        .unwrap();
        let repo_path = test_repo_path("raced.rs");
        let observation = std::iter::once(repo_path.clone()).collect::<BTreeSet<_>>();

        let before = authority_generation(&state);
        let commit = state.pending_commits.announce();
        let admission = exact_tree_admission(
            &state,
            Some(&observation),
            TreePublication::StandaloneUnlessACommitIsWaiting,
        )
        .unwrap();

        assert!(
            admission.yielded_to_pending_commit,
            "a commit inside the daemon must take this tick's publication"
        );
        assert!(
            admission.deltas.is_empty(),
            "a pass that admitted nothing must report nothing admitted"
        );
        assert_eq!(
            authority_generation(&state),
            before,
            "standing down must cost no repository-authority successor"
        );
        assert!(
            state
                .graph
                .resolved_tree()
                .artifact_at_path(&repo_path)
                .is_none(),
            "the derived graph must not run ahead of the authority the tick declined to move"
        );

        // The commit leaves, and the same tick admits normally again.
        drop(commit);
        let admission = exact_tree_admission(
            &state,
            Some(&observation),
            TreePublication::StandaloneUnlessACommitIsWaiting,
        )
        .unwrap();
        assert!(
            !admission.yielded_to_pending_commit,
            "the daemon is quiet again, so the next round admits"
        );
        assert_eq!(
            authority_generation(&state) - before,
            1,
            "one successor for the file, published by whichever pass got to it"
        );
    }

    /// A commit already inside the daemon takes the round with no wait at all.
    #[tokio::test]
    async fn a_round_stands_down_for_a_commit_that_is_already_inside_the_daemon() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let _commit = state.pending_commits.announce();

        assert!(
            wait_out_imminent_commit(&state, Duration::from_secs(3600), 0).await,
            "a commit inside the daemon is read directly, not waited for"
        );
    }

    /// A quiet daemon waits out the grace and then admits. The grace is what
    /// makes the yield reach the real cadence, because the commit's own
    /// process is still starting when the watcher notification lands. A round
    /// that refused to wait at all would only ever catch a commit that arrived
    /// during the walk.
    #[tokio::test]
    async fn a_round_waits_out_the_grace_and_then_admits_when_no_commit_arrives() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        let started = std::time::Instant::now();
        assert!(
            !wait_out_imminent_commit(&state, Duration::from_millis(2), 0).await,
            "no commit arrived, so the round admits"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait is bounded by the grace, not by the arrival it hoped for"
        );
    }

    /// A commit that announces itself during the grace still takes the round.
    /// This is the shape the defect was measured in: the tick reached its
    /// publication about 150ms before the commit reached the daemon.
    #[tokio::test]
    async fn a_round_stands_down_for_a_commit_that_arrives_during_the_grace() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        let announcing = Arc::clone(&state);
        let arriving = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _commit = announcing.pending_commits.announce();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        // A 200ms poll interval puts the grace at its one-second ceiling, which
        // is fifty times the arrival above.
        assert!(
            wait_out_imminent_commit(&state, Duration::from_millis(200), 0).await,
            "a commit that arrives inside the grace takes the round"
        );
        arriving.abort();
    }

    /// Write the announcement a client publishes before it does anything else,
    /// aged by `age_secs` so a test can put one past its window without
    /// sleeping through it.
    fn announce_approaching_commit(state: &DaemonState, age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0);
        kin_daemon_spawn::write_approaching_commit(
            state.layout.root(),
            &kin_daemon_spawn::ApproachingCommit {
                pid: std::process::id(),
                announced_unix: now.saturating_sub(age_secs),
            },
        );
    }

    /// The shape this defect was reopened on, in the order it actually happens.
    ///
    /// A client announces its commit, then waits for the store to open before it
    /// can send anything, and only then does its handler announce inside the
    /// daemon. On the run this was measured against, those two moments were
    /// 5,175ms apart and the tick's decision fell between them. The round has to
    /// stand down on the first of them, because the second one is not reachable
    /// in time by any wait a quiet daemon could afford to take.
    ///
    /// The arrival below is deliberately later than the grace can wait, so a
    /// round that could only see a commit already inside the daemon returns
    /// false rather than merely returning slowly. Both halves are asserted: the
    /// verdict, which cannot flake, and the moment it was reached.
    #[tokio::test]
    async fn a_round_stands_down_for_a_commit_that_announced_itself_before_it_could_arrive() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        announce_approaching_commit(&state, 0);

        let arriving = Arc::clone(&state);
        let entering = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _inside = arriving.pending_commits.announce();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        // A 200ms poll interval puts the grace at its one-second ceiling, which
        // expires a full second before the commit above reaches the daemon.
        let started = std::time::Instant::now();
        let stood_down = wait_out_imminent_commit(&state, Duration::from_millis(200), 0).await;
        let waited = started.elapsed();
        entering.abort();

        assert!(
            stood_down,
            "the announcement is readable before the round runs, so the round stands down for a \
             commit that could not possibly have arrived yet"
        );
        assert!(
            waited < Duration::from_millis(500),
            "the round must stand down on the announcement it can already read rather than wait \
             out the grace for an arrival two seconds away; it waited {waited:?}"
        );
    }

    /// The announcement's own bound. A client killed between writing its
    /// announcement and withdrawing it must not hold ambient admission off for
    /// the rest of the daemon's life, so the announcement expires on its own.
    #[tokio::test]
    async fn an_announcement_older_than_its_window_no_longer_takes_the_round() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        announce_approaching_commit(&state, 0);
        assert!(
            wait_out_imminent_commit(&state, Duration::from_millis(2), 0).await,
            "a fresh announcement takes the round, which is the control the assertion below \
             needs in order to mean anything"
        );

        announce_approaching_commit(
            &state,
            kin_daemon_spawn::APPROACHING_COMMIT_STALE_AFTER.as_secs() + 1,
        );
        assert!(
            !wait_out_imminent_commit(&state, Duration::from_millis(2), 0).await,
            "an announcement past its window is a client that is gone, and the round admits"
        );
    }

    /// The announcement is withdrawn when the client's run ends, however it
    /// ends, and the round stops standing down for it at once rather than at the
    /// end of its window.
    #[tokio::test]
    async fn a_withdrawn_announcement_stops_taking_the_round() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        announce_approaching_commit(&state, 0);
        assert!(
            wait_out_imminent_commit(&state, Duration::from_millis(2), 0).await,
            "the announcement takes the round while the client is still on its way"
        );

        kin_daemon_spawn::clear_approaching_commit(state.layout.root());
        assert!(
            !wait_out_imminent_commit(&state, Duration::from_millis(2), 0).await,
            "a withdrawn announcement leaves nothing to stand down for"
        );
    }

    /// The starvation bound. A commit that is announcing itself is holding the
    /// coordination gate or queued on it, so a round that proceeds past the
    /// bound queues behind it rather than racing it. What must not be possible
    /// is a client that keeps a commit handler inside the daemon without ever
    /// reaching authority holding ambient admission off forever.
    #[tokio::test]
    async fn consecutive_yields_are_bounded_so_a_permanent_commit_cannot_suppress_admission() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let _never_leaves = state.pending_commits.announce();

        for round in 0..MAX_CONSECUTIVE_COMMIT_YIELDS {
            assert!(
                wait_out_imminent_commit(&state, Duration::from_millis(2), round).await,
                "round {round} is within the bound and stands down"
            );
        }
        assert!(
            !wait_out_imminent_commit(
                &state,
                Duration::from_millis(2),
                MAX_CONSECUTIVE_COMMIT_YIELDS
            )
            .await,
            "past the bound the round admits, however loudly a commit is still announcing itself"
        );
    }

    /// The grace is worth a fraction of what it protects, never a fixed price.
    /// A repository whose publications are microseconds must not spend half a
    /// second holding off from one.
    #[test]
    fn the_grace_scales_with_what_a_publication_actually_costs() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let interval = Duration::from_millis(100);

        assert_eq!(
            commit_yield_grace(&state, interval),
            interval * COMMIT_YIELD_GRACE_INTERVALS,
            "a daemon that has never published has no measurement to scale by and uses the \
             interval bound"
        );

        state.record_authority_publication(Duration::from_micros(400));
        assert_eq!(
            commit_yield_grace(&state, interval),
            Duration::from_micros(50),
            "a publication measured in microseconds is not worth a wait measured in \
             milliseconds"
        );

        state.record_authority_publication(Duration::from_secs(12));
        assert_eq!(
            commit_yield_grace(&state, interval),
            interval * COMMIT_YIELD_GRACE_INTERVALS,
            "an eighth of twelve seconds is more than the interval bound allows"
        );
        assert!(
            commit_yield_grace(&state, Duration::from_secs(60)) <= COMMIT_YIELD_GRACE_CEILING,
            "no poll cadence may turn the grace into a stall"
        );
    }

    /// FIR-2466. The daemon may not publish its endpoint on a promise the loop
    /// never keeps, so the signal fires even when the loop never reaches its
    /// watcher.
    #[test]
    fn a_watch_signal_fires_on_drop_when_the_loop_never_arms() {
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        {
            let _armed = WatchArmed::new(tx);
        }
        assert_eq!(
            rx.try_recv(),
            Ok(()),
            "a dropped WatchArmed must release the daemon; a loop that ends before building a \
             watcher would otherwise hold the endpoint back forever"
        );
    }

    /// Arming is once. A second call after an explicit arm must not panic and
    /// must not send again, because the receiver is a one-shot.
    #[test]
    fn a_watch_signal_arms_once_and_the_later_drop_is_silent() {
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let mut armed = WatchArmed::new(tx);
        armed.arm();
        armed.arm();
        drop(armed);
        assert_eq!(rx.try_recv(), Ok(()), "the arm reaches the daemon");
    }

    /// A store that records no complete admission names no window, so the loop
    /// falls back to admitting nothing at startup rather than proposing the
    /// whole working copy.
    #[test]
    fn a_store_with_no_admission_marker_opens_no_catch_up_window() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        assert!(
            matches!(
                kin_core::last_admission::read(&state.layout),
                kin_core::last_admission::LastAdmissionRead::Absent
            ),
            "the control this assertion rests on: a fresh store carries no marker"
        );
        assert_eq!(
            startup_catch_up_window(&state),
            None,
            "with no lower bound the pass would propose the entire working copy, which is the \
             sweep startup must never perform"
        );
    }

    /// A recorded marker opens the window at its own instant, which is what
    /// bounds the catch-up to the stretch nothing was watching.
    #[test]
    fn a_recorded_admission_marker_opens_the_window_at_its_own_instant() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        kin_core::last_admission::write(
            &state.layout,
            &kin_core::last_admission::LastAdmission::new(at, 7),
        )
        .unwrap();

        assert_eq!(
            startup_catch_up_window(&state),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            "the window opens at the last complete admission, not at process start"
        );
    }

    /// A marker stamped before the epoch clamps rather than wrapping. A wrap
    /// would move the window to the far future, which loses every file.
    #[test]
    fn a_pre_epoch_marker_clamps_the_window_to_the_epoch() {
        let before = chrono::DateTime::from_timestamp(-10, 0).unwrap();
        assert_eq!(unix_instant(before), SystemTime::UNIX_EPOCH);
        let after = chrono::DateTime::from_timestamp(5, 250_000_000).unwrap();
        assert_eq!(
            unix_instant(after),
            SystemTime::UNIX_EPOCH + Duration::new(5, 250_000_000),
            "the ordinary case is not clamped, which is the control for the arm above"
        );
    }

    /// FIR-2499. The catch-up names what the host changed inside the window and
    /// nothing older, and what it names is admissible by the ordinary ambient
    /// path.
    ///
    /// Modification times are set outright rather than slept for, so the two
    /// arms sit on either side of the window by construction instead of by
    /// racing a filesystem's clock granularity.
    #[test]
    fn the_catch_up_names_host_paths_changed_inside_the_window_and_no_others() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        let before = repo.path().join("settled.rs");
        std::fs::write(&before, b"pub fn settled() -> u32 { 1 }\n").unwrap();
        stamp_modified(
            &before,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
        );

        let after = repo.path().join("written_while_nothing_watched.rs");
        std::fs::write(&after, b"pub fn written() -> u32 { 2 }\n").unwrap();
        stamp_modified(
            &after,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000),
        );

        let window = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
        let planned = plan_catch_up_events(&state, window).unwrap();
        let named = event_paths(&planned);
        // The plan speaks in the working directory the state is bound to, which
        // the layout resolved; a tempdir path is the unresolved form of the
        // same entry, so the two are compared by leaf.
        let named = named
            .iter()
            .filter_map(|path| path.file_name())
            .map(|leaf| leaf.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let after_leaf = "written_while_nothing_watched.rs".to_string();
        let before_leaf = "settled.rs".to_string();

        assert!(
            named.contains(&after_leaf),
            "a file written after the last admission is exactly what nothing observed: {named:?}"
        );
        assert!(
            !named.contains(&before_leaf),
            "a file older than the window was already covered by that admission: {named:?}"
        );

        // What the catch-up plans has to be admissible by the path it feeds,
        // or the plan is a list nothing acts on.
        let admitted = admit_file_event_ambient(&state, &FileEvent::Changed(after)).unwrap();
        assert!(
            matches!(admitted, AdmittedFileEvent::Regular { .. }),
            "the catch-up's own event must reach the tree: {admitted:?}"
        );
        assert!(
            tree_entry(&state, "written_while_nothing_watched.rs").is_some(),
            "the file the graph never met is what the catch-up exists to admit"
        );
    }

    /// The rules the catch-up walk shares with the content walk. An ignored
    /// path is excluded whatever its modification time says, so the catch-up
    /// cannot admit what an ordinary tick would refuse.
    #[test]
    fn the_catch_up_skips_a_path_the_ignore_rules_exclude() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join(".kinignore"), b"secrets.rs\n").unwrap();
        let state = open_test_state(&repo);

        let ignored = repo.path().join("secrets.rs");
        std::fs::write(&ignored, b"pub fn secret() -> u32 { 3 }\n").unwrap();
        stamp_modified(
            &ignored,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000),
        );
        let visible = repo.path().join("visible.rs");
        std::fs::write(&visible, b"pub fn visible() -> u32 { 4 }\n").unwrap();
        stamp_modified(
            &visible,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000),
        );

        let window = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
        let named = event_paths(&plan_catch_up_events(&state, window).unwrap())
            .iter()
            .filter_map(|path| path.file_name())
            .map(|leaf| leaf.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(
            named.contains(&"visible.rs".to_string()),
            "the positive control: an ordinary path inside the window is named: {named:?}"
        );
        assert!(
            !named.contains(&"secrets.rs".to_string()),
            "the catch-up walks under the same rules a tick does: {named:?}"
        );
    }

    /// FIR-2499. A path graph truth already tracks is projection drift, not
    /// catch-up work, however recently the host touched it.
    ///
    /// Repository authority holds bytes for a tracked path, so a host edit to
    /// one is what `kin doctor --drift` reports and `kin doctor --heal`
    /// repairs. A catch-up that took it would advance the workspace over
    /// graph-owned content at daemon start and empty the report an operator is
    /// about to read. The untracked file beside it is the positive control:
    /// same directory, same window, and it is still named.
    #[test]
    fn the_catch_up_leaves_a_tracked_path_to_the_drift_report() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        let tracked = repo.path().join("tracked.rs");
        std::fs::write(&tracked, b"pub fn tracked() -> u32 { 1 }\n").unwrap();
        admit_file_event_ambient(&state, &FileEvent::Changed(tracked.clone())).unwrap();
        assert!(
            tree_entry(&state, "tracked.rs").is_some(),
            "the fixture needs this path tracked before the window is opened"
        );
        std::fs::write(&tracked, b"pub fn tracked() -> u32 { 2 }\n").unwrap();
        stamp_modified(
            &tracked,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000),
        );

        let untracked = repo.path().join("untracked.rs");
        std::fs::write(&untracked, b"pub fn untracked() -> u32 { 3 }\n").unwrap();
        stamp_modified(
            &untracked,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000),
        );

        let window = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
        let named = event_paths(&plan_catch_up_events(&state, window).unwrap())
            .iter()
            .filter_map(|path| path.file_name())
            .map(|leaf| leaf.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(
            named.contains(&"untracked.rs".to_string()),
            "the positive control: content the graph has never met is still named: {named:?}"
        );
        assert!(
            !named.contains(&"tracked.rs".to_string()),
            "a tracked path edited off-watch is drift for `kin doctor`, not a silent catch-up \
             admission: {named:?}"
        );
    }

    /// FIR-2499. A directory graph truth has never met is disclosed, not swept
    /// in.
    ///
    /// A directory arriving whole is a clone, a move, an unpacked archive or a
    /// renamed control directory, and a move restamps every entry it carries,
    /// so modification times cannot tell that content from authored work.
    /// Admitting one at daemon start is the working-copy sweep startup must
    /// never perform. The file beside the tracked one is the positive control:
    /// it sits where the graph already looks, so the window still reaches it.
    #[test]
    fn the_catch_up_declines_a_directory_the_graph_has_never_met() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);

        let known = repo.path().join("known.rs");
        std::fs::write(&known, b"pub fn known() -> u32 { 1 }\n").unwrap();
        admit_file_event_ambient(&state, &FileEvent::Changed(known)).unwrap();
        assert!(
            tree_entry(&state, "known.rs").is_some(),
            "the fixture needs the repository root to hold tracked content"
        );

        let beside = repo.path().join("beside_known.rs");
        std::fs::write(&beside, b"pub fn beside() -> u32 { 2 }\n").unwrap();
        stamp_modified(
            &beside,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000),
        );

        let arrived = repo.path().join("arrived_whole");
        std::fs::create_dir_all(&arrived).unwrap();
        let carried = arrived.join("carried.rs");
        std::fs::write(&carried, b"pub fn carried() -> u32 { 3 }\n").unwrap();
        stamp_modified(
            &carried,
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000),
        );

        let window = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
        let named = event_paths(&plan_catch_up_events(&state, window).unwrap())
            .iter()
            .filter_map(|path| path.file_name())
            .map(|leaf| leaf.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(
            named.contains(&"beside_known.rs".to_string()),
            "the positive control: a new file where the graph already looks is named: {named:?}"
        );
        assert!(
            !named.contains(&"carried.rs".to_string()),
            "a directory the graph has never met is for the behind disclosure and `kin admit`, \
             not for a startup sweep: {named:?}"
        );
    }

    /// The host paths a planned batch names.
    fn event_paths(events: &[FileEvent]) -> Vec<PathBuf> {
        events
            .iter()
            .map(|event| {
                let (FileEvent::Changed(path) | FileEvent::Removed(path)) = event;
                path.clone()
            })
            .collect()
    }

    /// Set a host entry's modification time outright.
    ///
    /// Both stamps are written because setting only one is refused on some
    /// hosts, and the access time is not what any assertion here reads.
    fn stamp_modified(path: &Path, at: SystemTime) {
        let handle = std::fs::File::options().write(true).open(path).unwrap();
        handle
            .set_times(std::fs::FileTimes::new().set_accessed(at).set_modified(at))
            .unwrap();
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap().modified().unwrap(),
            at,
            "the stamp has to have applied, or every assertion resting on it is about the \
             file's real age instead"
        );
    }

    /// Build the artifact-to-artifact edge shape the cross-file linker mints
    /// for a file-level import, which is the class of relation nothing else
    /// collects when its file is deleted.
    fn artifact_edge(
        src: kin_model::ArtifactId,
        dst: kin_model::ArtifactId,
        kind: kin_model::RelationKind,
    ) -> kin_model::Relation {
        kin_model::Relation {
            id: kin_model::RelationId::new(),
            kind,
            src: kin_model::GraphNodeId::Artifact(src),
            dst: kin_model::GraphNodeId::Artifact(dst),
            confidence: 1.0,
            origin: kin_model::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    fn artifact_at(state: &DaemonState, path: &str) -> kin_model::ArtifactId {
        state
            .graph
            .artifact_id_at_path(&test_repo_path(path))
            .unwrap_or_else(|| panic!("{path} must be admitted before the test asks about it"))
    }

    /// FIR-2607. A file whose artifact is named by a relation can be deleted.
    ///
    /// Both shapes the linker actually produces are covered: the outgoing
    /// import edge to another artifact, and the parse-coverage self-loop every
    /// indexed file carries. kin-db validates every relation the graph holds
    /// against the staged tree on each transaction, so either one left standing
    /// fails the whole removal, not just the edge. Before the fix this test
    /// fails with `transaction relation <id> has unadmitted source endpoint
    /// artifact:<id>`, which is the exact refusal that made a repository unable
    /// to commit at all until the file was emptied first.
    #[test]
    fn a_removal_takes_the_relations_bound_to_the_departing_artifact() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let leaving = repo.path().join("leaving.rs");
        let staying = repo.path().join("staying.rs");
        std::fs::write(&leaving, b"pub fn leaving() -> u32 { 1 }\n").unwrap();
        std::fs::write(&staying, b"pub fn staying() -> u32 { 2 }\n").unwrap();
        admit_file_event(&state, &FileEvent::Changed(leaving.clone())).unwrap();
        admit_file_event(&state, &FileEvent::Changed(staying.clone())).unwrap();

        let leaving_id = artifact_at(&state, "leaving.rs");
        let staying_id = artifact_at(&state, "staying.rs");
        let import = artifact_edge(leaving_id, staying_id, kin_model::RelationKind::Imports);
        let coverage = artifact_edge(leaving_id, leaving_id, kin_model::RelationKind::DependsOn);
        state.graph.upsert_relation(&import).unwrap();
        state.graph.upsert_relation(&coverage).unwrap();

        std::fs::remove_file(&leaving).unwrap();
        let admitted = admit_file_event_ambient(&state, &FileEvent::Removed(leaving))
            .expect("a removal must collect the edges bound to the artifact it drops");

        assert!(matches!(admitted, AdmittedFileEvent::Removed { .. }));
        assert!(
            tree_entry(&state, "leaving.rs").is_none(),
            "the artifact left the tree"
        );
        assert!(
            state
                .graph
                .get_all_relations_for_node(&kin_model::GraphNodeId::Artifact(leaving_id))
                .unwrap()
                .is_empty(),
            "and every edge naming it left with it"
        );
        assert!(
            tree_entry(&state, "staying.rs").is_some(),
            "the destination artifact is untouched: only the departing endpoint's edges go"
        );
    }

    /// FIR-2607, the second half. A refusal a user can act on.
    ///
    /// The raw storage message names two uuids and offers nothing to do. This
    /// asserts the surface a user meets names the path being dropped and the
    /// two-step retirement that clears the edges, so the message is about their
    /// repository rather than about kin's internals.
    #[test]
    fn a_stranded_endpoint_refusal_names_the_path_and_the_way_out() {
        let raw = DaemonError::Graph(kin_db::KinDbError::StorageError(
            "transaction relation 6b30c139-1c2a-a133-d17b-2625e60d3df9 has unadmitted source \
             endpoint artifact:f4d9e1db-d7b2-4fd9-912c-2809f331331b"
                .to_string(),
        ));
        let deltas = vec![TreeDelta::Removed {
            artifact_id: kin_model::ArtifactId::new(),
            old: kin_model::LocatedEntry::new(
                test_repo_path("notekeeper/search.py"),
                TreeEntry::blob(Hash256::from_bytes([7; 32]), false),
            ),
        }];

        let named = name_stranded_endpoint_refusal(raw, &deltas).to_string();

        assert!(
            named.contains("notekeeper/search.py"),
            "the refusal names the path being dropped: {named}"
        );
        assert!(
            named.contains("fix: empty the file and commit"),
            "and carries the retirement that clears the edges: {named}"
        );
        assert!(
            named.contains("6b30c139-1c2a-a133-d17b-2625e60d3df9"),
            "without losing the identifiers a report needs: {named}"
        );
    }

    /// An unrelated failure is handed back untouched, so the naming above can
    /// never dress up a refusal it does not understand.
    #[test]
    fn an_unrelated_refusal_is_not_dressed_up_as_a_stranded_endpoint() {
        let raw = DaemonError::Graph(kin_db::KinDbError::StorageError(
            "transaction adds existing entity 1056cc39-df63-5f0b-9d85-a161fb2c882f".to_string(),
        ));

        let passed_through = name_stranded_endpoint_refusal(raw, &[]).to_string();

        assert!(
            passed_through.contains("transaction adds existing entity"),
            "an unrelated storage refusal keeps its own words: {passed_through}"
        );
        assert!(
            !passed_through.contains("fix: empty the file"),
            "and gains no advice that would not help: {passed_through}"
        );
    }

    /// FIR-2606. An admitted source path the graph holds no entities for is
    /// offered for re-derivation.
    ///
    /// This is the state a daemon leaves behind when it ends between a write
    /// and the commit that would have published the entities: the artifact is
    /// admitted at exactly the bytes on disk, so no tree delta and no watcher
    /// event ever names it again, and every query answers about it as an
    /// absence. Recovering it is what stops that from being permanent.
    #[test]
    fn an_admitted_source_path_with_no_entities_is_offered_for_re_derivation() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let source = repo.path().join("stranded.rs");
        std::fs::write(&source, b"pub fn stranded() -> u32 { 1 }\n").unwrap();
        admit_file_event(&state, &FileEvent::Changed(source.clone())).unwrap();

        let owed = plan_unenriched_source_events(&state).unwrap();

        // Compared by repository-relative name: the host root reaches this
        // test through /var and comes back through /private/var, and the
        // subject here is which path is owed, not how the host spells it.
        let named = owed
            .iter()
            .map(|event| {
                let (FileEvent::Changed(path) | FileEvent::Removed(path)) = event;
                path.file_name().unwrap().to_string_lossy().to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            named,
            vec![source.file_name().unwrap().to_string_lossy().to_string()],
            "an admitted source path with no entities is exactly what needs re-deriving"
        );
    }

    /// The control that keeps the repair narrow: a path whose entities the
    /// graph already holds is never re-derived, so this cannot become a sweep
    /// that re-parses the working copy on every daemon start.
    #[test]
    fn an_admitted_source_path_that_carries_entities_is_left_alone() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let source = repo.path().join("enriched.rs");
        std::fs::write(&source, b"pub fn enriched() -> u32 { 1 }\n").unwrap();
        admit_file_event(&state, &FileEvent::Changed(source)).unwrap();
        assert_eq!(
            plan_unenriched_source_events(&state).unwrap().len(),
            1,
            "the positive control: before its entities land the path is owed a re-derivation"
        );

        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![kin_model::EntityDelta::Added {
                    new: test_entity("enriched", "enriched.rs"),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                ..TransactionDelta::default()
            })
            .unwrap();

        assert!(
            plan_unenriched_source_events(&state).unwrap().is_empty(),
            "and once the graph holds an entity for it, nothing is owed"
        );
    }

    /// A file no language adapter parses is enriched by a shallow, structured
    /// or opaque facet instead, so it has no entities by design and must not be
    /// proposed forever.
    #[test]
    fn an_admitted_path_with_no_entity_adapter_is_not_offered() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        let notes = repo.path().join("NOTES.txt");
        std::fs::write(&notes, b"not a language this repository parses\n").unwrap();
        admit_file_event(&state, &FileEvent::Changed(notes)).unwrap();

        assert!(
            plan_unenriched_source_events(&state).unwrap().is_empty(),
            "a path with no entity adapter is not owed a re-parse"
        );
    }

    fn test_entity(name: &str, file_path: &str) -> kin_model::Entity {
        kin_model::Entity {
            id: kin_model::EntityId::new(),
            kind: kin_model::EntityKind::Function,
            name: name.to_string(),
            language: kin_model::LanguageId::Rust,
            fingerprint: kin_model::SemanticFingerprint {
                algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file_path)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: kin_model::Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }
}

/// Decide whether a filesystem-sync tick's bulk deletions should be WITHHELD as
/// a suspected mass-wipe. Returns true to block. Delegates the collapse
/// threshold to the shared `graph_collapse_is_wipe` predicate so the fs-sync
/// guard and the shutdown guard stay consistent (>75% gone, baseline ≥ 16). An
/// explicit operator override (`allow_override`) always permits the deletions.
pub(crate) fn should_block_mass_deletion(
    removed: u64,
    total_graph_files: u64,
    allow_override: bool,
) -> bool {
    if allow_override {
        return false;
    }
    let surviving = total_graph_files.saturating_sub(removed);
    crate::state::graph_collapse_is_wipe(surviving, total_graph_files)
}

#[tracing::instrument(skip(state))]
pub async fn sync_filesystem_with_graph(state: &DaemonState) -> Result<()> {
    let _coordination = state.coordination_gate.lock().await;
    sync_filesystem_with_graph_under_coordination(state).await
}

/// Synchronize the host checkout while the caller holds `coordination_gate`.
///
/// This split lets `/commands/commit` hold one uninterrupted authority gate
/// across forced admission, delta construction, and branch publication
/// without recursively acquiring the non-reentrant mutex.
pub(crate) async fn sync_filesystem_with_graph_under_coordination(
    state: &DaemonState,
) -> Result<()> {
    sync_filesystem_with_graph_publishing(state, TreePublication::Standalone)
        .await
        .map(|_| ())
}

/// Admit the host checkout without publishing its tree transition, and return
/// the transition for the caller to carry.
///
/// `/commands/commit` uses this so one repository-authority successor carries
/// both the admitted exact tree and the semantic change it produces. Preparing
/// a successor and persisting the store is O(store) on both sides of the
/// commit, so publishing the tree on its own first makes a one-line change pay
/// that cost twice.
///
/// The caller must hold `coordination_gate` across this call and its own
/// publication, and must publish the returned tree standalone if its
/// transaction never reaches authority. `None` means nothing moved, or that
/// the transition was not eligible to be deferred and has already been
/// published here.
pub(crate) async fn sync_filesystem_with_graph_deferring_tree_publication(
    state: &DaemonState,
) -> Result<Option<crate::repository_commit::AdmittedWorkspaceTree>> {
    sync_filesystem_with_graph_publishing(state, TreePublication::DeferredToCaller).await
}

async fn sync_filesystem_with_graph_publishing(
    state: &DaemonState,
    publication: TreePublication,
) -> Result<Option<crate::repository_commit::AdmittedWorkspaceTree>> {
    let mut deferred = None;
    match sync_filesystem_with_graph_publishing_inner(state, publication, &mut deferred).await {
        Ok(()) => Ok(deferred),
        Err(error) => {
            if let Some(admitted) = deferred {
                publish_deferred_tree_after_failure(state, &admitted);
            }
            Err(error)
        }
    }
}

/// The exact tree repository authority currently records for this workspace.
///
/// The derived graph's counterpart, and the answer `kin status` reports while
/// `kin graph status` reports the graph's own. The two agreeing is the
/// invariant a deferral is opened against and the one a failed commit has to
/// restore.
fn authority_workspace_tree(state: &DaemonState) -> Result<kin_model::ResolvedTree> {
    let authority_context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?;
    crate::repository_commit::authority_workspace_tree(&authority_context)
}

/// Return the derived graph to the exact tree repository authority holds.
///
/// The one reset that is correct whatever went wrong. Rolling the admitted
/// deltas back would restore the tree the pass planned out of, which is right
/// when authority stood still and wrong when it moved, and those two cases are
/// indistinguishable from the deltas alone. Reading authority answers both: the
/// graph is a derived view, so the state it must return to is whatever
/// authority currently holds, not whatever it held a moment ago.
///
/// Enrichment for the artifacts this removes goes first, in the order every
/// other tree removal uses, because kin-db refuses a transition that leaves an
/// entity on a path the staged tree no longer carries. Enrichment for a path
/// whose content this rolls back is left alone: the working copy still holds
/// the newer bytes, so the next admission re-derives the same transition and
/// re-enriches from them, and evicting it here would delete answers the store
/// can still give.
fn reset_derived_graph_to_authority_tree(state: &DaemonState) -> Result<Vec<TreeDelta>> {
    let authority_tree = authority_workspace_tree(state)?;
    let graph_tree = state.graph.resolved_tree();
    if graph_tree == authority_tree {
        return Ok(Vec::new());
    }
    let deltas = kin_core::exact_tree_correction(&graph_tree, &authority_tree)?;
    evict_enrichment_for_removed_paths(state, &deltas)?;
    state.graph.apply_transaction_delta(&TransactionDelta {
        entity_deltas: Vec::new(),
        relation_deltas: Vec::new(),
        tree_deltas: deltas.clone(),
        ..TransactionDelta::default()
    })?;
    // Every graph mutation bumps the counter, and this one removes artifacts a
    // projection reader may already hold. Skipping it would leave a VFS client
    // materializing a tree the graph has just given up, and would leave the
    // reset out of background persistence, so a restart would reload the graph
    // that was ahead.
    state.bump_version();
    Ok(deltas)
}

/// Close a deferral whose caller will never publish it.
///
/// The derived graph already carries the admitted tree, so leaving it
/// unpublished would leave the graph ahead of repository authority, and every
/// later admission plans its transition out of the graph's tree and would be
/// refused against the older authority tree. Publishing here restores the
/// ordering a standalone admission would have established, which is exactly
/// the state a failed commit leaves behind today.
///
/// Publishing forward is the first recovery and not the only one, because it
/// cannot work when the reason the transaction was refused is a property of the
/// tree itself. Untracked sensitive content is exactly that shape: the
/// credential scanner refuses the artifact inside the repository transaction, so
/// the standalone publication carrying the same artifact is refused for the same
/// reason, and every retry after it is too. Rolling the derived graph back to
/// what authority holds is the second recovery, and it always terminates: the
/// tree it resets to is one repository authority has already accepted.
///
/// What the user sees turns on this. A daemon that rolls back answers the next
/// commit with the refusal that actually stopped it, every time; a daemon that
/// stays ahead answers with a tree mismatch, then an admission that reports
/// nothing changed, then a projection conflict about a path that is simply
/// there, none of which name the cause.
///
/// Only a rollback that fails as well leaves the daemon wedged, and that is
/// still reported at error level and recorded on the reconcile probes, so
/// `/health`, `/commands/resources`, `kin graph status`, `kin admit`, and
/// `kin doctor` all name the restart rather than leaving a reader to infer it
/// from a refusal.
pub(crate) fn publish_deferred_tree_after_failure(
    state: &DaemonState,
    admitted: &crate::repository_commit::AdmittedWorkspaceTree,
) {
    match publish_exact_workspace_tree(state, admitted) {
        Ok(_) => {
            // The deferral closed, so whatever earlier one did not is resolved:
            // this publication planned against the authority tree it just
            // advanced, which a graph running ahead of authority cannot do.
            state
                .background_work
                .reconcile()
                .clear_deferred_tree_wedge();
        }
        Err(publication_error) => match reset_derived_graph_to_authority_tree(state) {
            Ok(reverted) => {
                warn!(
                    error = %publication_error,
                    reverted = reverted.len(),
                    "the publication restoring a failed commit's deferred exact workspace tree was \
                     refused, so the derived graph was reset to the tree repository authority holds; \
                     the next admission plans out of that tree and reports the refusal that stopped \
                     this one"
                );
                // The graph and authority agree again, which is the whole of
                // what a wedge names. Clearing it here is what stops one refused
                // admission reporting a restart nobody has to perform.
                state
                    .background_work
                    .reconcile()
                    .clear_deferred_tree_wedge();
            }
            Err(reset_error) => {
                error!(
                    error = %publication_error,
                    reset_error = %reset_error,
                    "failed to publish the deferred exact workspace tree after the carrying \
                     transaction did not reach authority, and resetting the derived graph to the \
                     tree repository authority holds failed too; the derived graph is ahead of \
                     repository authority and this daemon must be restarted before it can admit \
                     again"
                );
                state
                    .background_work
                    .reconcile()
                    .record_deferred_tree_wedge(
                        format!(
                        "{publication_error}; resetting the derived graph to the authority tree \
                         failed too: {reset_error}"
                    ),
                        Instant::now(),
                    );
            }
        },
    }
}

async fn sync_filesystem_with_graph_publishing_inner(
    state: &DaemonState,
    publication: TreePublication,
    deferred_out: &mut Option<crate::repository_commit::AdmittedWorkspaceTree>,
) -> Result<()> {
    if state.filesystem_reconcile_disabled() {
        debug!(
            env = DISABLE_FILESYSTEM_RECONCILE_ENV,
            "filesystem sync skipped; remote graph remains authoritative"
        );
        return Ok(());
    }

    let working_dir = state.layout.working_dir();
    if is_bare_repository(working_dir) {
        debug!(working_dir = %working_dir.display(), "working directory is a bare Git repository; skipping filesystem sync");
        return Ok(());
    }

    let graph_mutation = state.begin_graph_authority_mutation();
    // An explicit admission seam. Everything the working copy holds crosses
    // the compare-and-swap here, which is why `/commands/commit` calls it
    // rather than relying on whatever the watcher happened to observe.
    let mut exact_admission = exact_tree_admission(state, None, publication)?;
    // Recorded before anything below can fail, so a pass that dies part way
    // through enrichment still hands the deferral back to be closed.
    *deferred_out = exact_admission.deferred_tree.take();
    // An admitted source path the graph holds no entities for is re-derived on
    // this seam too, and it is why the early return below cannot key on the
    // tree transition alone. Entity derivation is not durable on its own: a
    // daemon that ends between the write and the commit takes it with it, and
    // what it leaves behind is an artifact admitted at exactly the bytes on
    // disk, which produces no tree delta here and no watcher event ever again.
    // Without this the file stays admitted and unqueryable through every later
    // commit, which is exactly how one module dropped out of a store and stayed
    // out (FIR-2606).
    let unenriched = plan_unenriched_source_events(state)?;
    if exact_admission.deltas.is_empty() && unenriched.is_empty() {
        drop(graph_mutation);
        return Ok(());
    }
    if !unenriched.is_empty() {
        warn!(
            count = unenriched.len(),
            "admitted source paths carry no entities, so nothing can query them; re-deriving \
             them into this change"
        );
    }
    let mut events = exact_admission.semantic_events;
    events.extend(unenriched);
    let events = dedup_file_events(events);

    info!(
        count = events.len(),
        artifacts = exact_admission.deltas.len(),
        "admitted one complete exact-tree transition on daemon tick/startup"
    );

    // Optional semantic enrichment follows exact admission. Parser support
    // never controls repository membership.
    let mut reconciler = state.reconciler.write().await;
    let mut graph_changed = true;
    let mut projection_changed = ProjectionChangedSet::default();
    let enrichment_pipeline = IndexPipeline::new();
    state.bump_version();

    for event in events {
        let admitted = match admit_file_event_with_exact_tree(
            state,
            &event,
            &exact_admission.changed_paths,
        ) {
            Ok(admitted) => admitted,
            Err(error) => {
                warn!(error = %error, "failed to admit exact repository-tree entry during sync");
                state
                    .background_work
                    .reconcile()
                    .record_event_skipped(&error, Instant::now());
                continue;
            }
        };
        if matches!(
            admitted,
            AdmittedFileEvent::Ignored | AdmittedFileEvent::Untracked { .. }
        ) {
            continue;
        }
        let tree_changed = admitted.tree_changed();
        // The complete exact-tree transaction is already graph authority.
        if tree_changed && !matches!(&admitted, AdmittedFileEvent::Removed { .. }) {
            graph_changed = true;
        }
        let path = match &event {
            FileEvent::Changed(path) | FileEvent::Removed(path) => path,
        };
        let admitted_repo_path = match &admitted {
            AdmittedFileEvent::Regular { repo_path, .. }
            | AdmittedFileEvent::Symlink { repo_path, .. }
            | AdmittedFileEvent::Removed { repo_path, .. } => repo_path,
            AdmittedFileEvent::Untracked { .. } | AdmittedFileEvent::Ignored => unreachable!(),
        };
        if !host_entry_matches_graph(state, path, admitted_repo_path)? {
            return Err(DaemonError::Io(std::io::Error::other(format!(
                "host entry changed after exact-tree admission: {admitted_repo_path}"
            ))));
        }

        let (semantic_event, semantic_repo_path) = match admitted {
            AdmittedFileEvent::Regular {
                repo_path,
                file_id,
                content,
                blob_hash,
                entry,
                ..
            } => {
                let Some(file_id) = file_id else {
                    debug!(
                        file = %repo_path,
                        ?entry,
                        "admitted byte-exact non-UTF-8 path without UTF-8 semantic enrichment"
                    );
                    continue;
                };
                let classification = FileClassifier::classify_with_content(path, &content);
                if classification != FileClassification::EntitySource {
                    match enrichment_pipeline.index_any_content(&file_id, &content, blob_hash) {
                        Ok(indexed) => match persist_non_entity_enrichment(state, indexed) {
                            Ok((file_id, cleanup)) => {
                                projection_changed.remove(file_id.clone());
                                for id in cleanup.removed_entities {
                                    state.emit_event(DaemonEvent::EntityChanged {
                                        entity_id: id,
                                        change_type: ChangeType::Deleted,
                                        file_path: Some(file_id.0.clone()),
                                        session_id: None,
                                    });
                                }
                                graph_changed = true;
                            }
                            Err(error) => warn!(
                                file = %file_id,
                                error = %error,
                                "tree entry admitted during sync but facet persistence failed"
                            ),
                        },
                        Err(error) => warn!(
                            file = %file_id,
                            error = %error,
                            "tree entry admitted during sync but optional enrichment failed"
                        ),
                    }
                    continue;
                }

                match clear_incompatible_facets(state, &file_id, EnrichmentFacet::EntitySource) {
                    Ok(cleanup) => graph_changed |= cleanup.changed,
                    Err(error) => warn!(
                        file = %file_id,
                        error = %error,
                        "tree entry admitted during sync but incompatible facet cleanup failed"
                    ),
                }
                (FileEvent::Changed(path.clone()), repo_path)
            }
            AdmittedFileEvent::Symlink {
                repo_path,
                file_id,
                entry,
                ..
            } => {
                let Some(file_id) = file_id else {
                    debug!(
                        file = %repo_path,
                        ?entry,
                        "admitted byte-exact non-UTF-8 symlink without UTF-8 enrichment"
                    );
                    continue;
                };
                match clear_incompatible_facets(state, &file_id, EnrichmentFacet::None) {
                    Ok(cleanup) => {
                        for id in cleanup.removed_entities {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: id,
                                change_type: ChangeType::Deleted,
                                file_path: Some(file_id.0.clone()),
                                session_id: None,
                            });
                        }
                        projection_changed.remove(file_id.clone());
                        graph_changed |= cleanup.changed;
                        debug!(
                            file = %file_id,
                            ?entry,
                            "admitted symlink during exact-tree sync"
                        );
                    }
                    Err(error) => warn!(
                        file = %file_id,
                        error = %error,
                        "symlink admitted during sync but facet cleanup failed"
                    ),
                }
                continue;
            }
            AdmittedFileEvent::Removed {
                repo_path,
                file_id,
                tree_changed,
            } => {
                if !tree_changed {
                    continue;
                }
                match finalize_tree_removal(state, file_id.as_ref(), tree_changed) {
                    Ok(cleanup) => {
                        if let Some(file_id) = &file_id {
                            projection_changed.remove(file_id.clone());
                            for id in cleanup.removed_entities {
                                state.emit_event(DaemonEvent::EntityChanged {
                                    entity_id: id,
                                    change_type: ChangeType::Deleted,
                                    file_path: Some(file_id.0.clone()),
                                    session_id: None,
                                });
                            }
                        }
                        graph_changed = true;
                        debug!(file = %repo_path, "removed exact tree entry during complete sync");
                    }
                    Err(error) => warn!(
                        file = %repo_path,
                        error = %error,
                        "failed to remove repository entry after complete sync"
                    ),
                }
                continue;
            }
            AdmittedFileEvent::Untracked { .. } | AdmittedFileEvent::Ignored => unreachable!(),
        };

        match reconciler.reconcile_file_change(&semantic_event, &state.blobs, state.graph.as_ref())
        {
            Ok(result) => {
                let (outcome, delta) = result.into_parts();
                use kin_reconcile::ReconcileOutcome;
                let should_apply = matches!(
                    &outcome,
                    ReconcileOutcome::Updated { .. } | ReconcileOutcome::FileRemoved { .. }
                );
                if should_apply {
                    if !host_entry_matches_graph(state, path, &semantic_repo_path)? {
                        return Err(DaemonError::Io(std::io::Error::other(format!(
                            "host entry changed during semantic reconciliation: \
                             {semantic_repo_path}"
                        ))));
                    }
                    if let Err(e) = state.graph.apply_transaction_delta(&delta) {
                        warn!(error = %e, "failed to apply synced transaction into primary graph");
                        continue;
                    }
                    // The file's declarations just moved, so whatever a language
                    // server said about them was said at positions this delta
                    // retired. The marker claims the opposite, and until it is
                    // retired the next sweep skips this file, which is how a
                    // comment-only commit's edge loss survived two recovery
                    // sweeps on the rc0547b store (FIR-2598).
                    crate::daemon::retire_enrichment_marker(
                        state,
                        &[semantic_repo_path.to_string()],
                    );
                    if let Err(e) =
                        state.persist_projection_truth_from_reconcile(&reconciler, &outcome)
                    {
                        warn!(error = %e, "failed to persist projection truth after sync");
                    }
                    projection_changed.record_reconcile_outcome(&outcome);

                    if let ReconcileOutcome::FileRemoved {
                        removed, file_id, ..
                    } = &outcome
                    {
                        match clear_incompatible_facets(state, file_id, EnrichmentFacet::None) {
                            Ok(_) => {
                                projection_changed.remove(file_id.clone());
                            }
                            Err(error) => warn!(
                                file = %file_id,
                                error = %error,
                                "removed exact tree entry but failed to clear every facet"
                            ),
                        }

                        for id in removed {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Deleted,
                                file_path: Some(file_id.0.clone()),
                                // FS-reconcile loop: anonymous, no owning session.
                                session_id: None,
                            });
                        }
                    }

                    graph_changed = true;
                }
            }
            Err(e) => {
                warn!(
                    file = %semantic_repo_path,
                    error = %e,
                    "sync reconciliation error for event; dropping it and leaving this path's enrichment stale"
                );
                state
                    .background_work
                    .reconcile()
                    .record_event_skipped(format!("{semantic_repo_path}: {e}"), Instant::now());
            }
        }
    }

    drop(reconciler);

    if graph_changed {
        state.mark_dirty();
        state.bump_version();
    }
    drop(graph_mutation);

    if graph_changed {
        let projection_result = if projection_changed.is_empty() {
            state.rebuild_projection().await
        } else {
            state.refresh_projection(&projection_changed).await
        };
        if let Err(e) = projection_result {
            error!(error = %e, "failed to refresh projection after sync");
        }
    }

    Ok(())
}
