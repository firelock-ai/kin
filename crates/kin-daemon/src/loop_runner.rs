// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    RECON_PROCESSING,
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

/// Run the reconciliation loop until the cancellation token fires.
///
/// This is the main loop of the daemon. It:
/// 1. Watches the working directory for file changes (via `notify`)
/// 2. Drains batches of events
/// 3. For each event, runs the reconciler (file -> overlay)
/// 4. Projects overlay mutations back to files (overlay -> file)
///
fn is_bare_repository(dir: &std::path::Path) -> bool {
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
    Ignored,
}

impl AdmittedFileEvent {
    fn tree_changed(&self) -> bool {
        match self {
            Self::Regular { tree_changed, .. }
            | Self::Symlink { tree_changed, .. }
            | Self::Removed { tree_changed, .. } => *tree_changed,
            Self::Ignored => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnrichmentFacet {
    EntitySource,
    ShallowSyntax,
    StructuredArtifact,
    OpaqueArtifact,
    None,
}

#[derive(Debug, Default)]
struct FacetCleanup {
    removed_entities: Vec<EntityId>,
    changed: bool,
}

#[derive(Debug)]
struct ExactTreeAdmission {
    deltas: Vec<TreeDelta>,
    changed_paths: BTreeSet<RepoPath>,
    semantic_events: Vec<FileEvent>,
}

fn canonicalize_host_parent_preserving_leaf(path: &Path) -> std::io::Result<PathBuf> {
    let leaf = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "filesystem event has no repository entry name: {}",
                path.display()
            ),
        )
    })?;
    let mut unresolved = vec![leaf.to_os_string()];
    let mut ancestor = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "filesystem event has no parent directory: {}",
                path.display()
            ),
        )
    })?;

    loop {
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                for component in unresolved.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let component = ancestor.file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "filesystem event has no existing ancestor to establish repository containment: {}",
                            path.display()
                        ),
                    )
                })?;
                unresolved.push(component.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "filesystem event has no existing ancestor to establish repository containment: {}",
                            path.display()
                        ),
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn repo_path(path: &Path, working_dir: &Path) -> Result<Option<RepoPath>> {
    // Normalize the repository root and the event's nearest existing parent.
    // This treats macOS aliases such as /var and /private/var as the same
    // directory without dereferencing the final entry (which may itself be a
    // dangling symlink, or already removed). Resolving the parent also rejects
    // events that appear lexically beneath the repository but traverse a
    // directory symlink out of it.
    let canonical_root = working_dir.canonicalize().map_err(DaemonError::Io)?;
    let canonical_path = canonicalize_host_parent_preserving_leaf(path).map_err(DaemonError::Io)?;
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

/// Returns the authority generation this admission published, or `None` when
/// the desired tree already matched authority and nothing moved.
pub(crate) fn publish_exact_workspace_tree(
    state: &DaemonState,
    admitted: &crate::repository_commit::AdmittedWorkspaceTree,
) -> Result<Option<u64>> {
    let authority_context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?;
    let Some(admission) = crate::repository_commit::publish_workspace_tree(
        state.blobs.as_ref(),
        &authority_context,
        admitted,
        kin_model::OperationId::new(),
        kin_model::AuthorId::new(kin_core::whoami()),
    )?
    else {
        return Ok(None);
    };
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

/// Read the repository roots the next observation will be planned against.
pub(crate) fn current_authority_roots(state: &DaemonState) -> Result<kin_model::RootBundle> {
    let authority_context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?;
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let roots = authority.read_authority().roots().clone();
    Ok(roots)
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
/// `Some(paths)` is the ambient watcher path and is bounded twice. Only the
/// observed paths and their descendants may move, so one unrelated host event
/// cannot sweep the rest of the working copy into repository authority. And
/// only members the workspace already tracks may move at all, so ambient
/// observation revises graph-owned history but never enlarges it: a host path
/// the repository has never tracked becomes repository truth when a person
/// commits it, not because a watcher noticed it. That is what keeps untracked
/// host content from dirtying a workspace or gating a transition.
///
/// The scan itself stays complete either way, so a rename keeps one stable
/// artifact identity even when its two halves arrive in different notification
/// batches. Only the planned transition is bounded.
fn exact_tree_admission(
    state: &DaemonState,
    observation: Option<&BTreeSet<RepoPath>>,
) -> Result<ExactTreeAdmission> {
    let working_dir = state.layout.working_dir();
    // Read the authority roots the observation is about to be planned against.
    // Publication compare-and-swaps on this bundle, so a repository that moves
    // while the host walk is running fails the whole admission instead of
    // having its desired tree replanned onto the newer authority.
    let expected_roots = current_authority_roots(state)?;
    let previous = state.graph.resolved_tree();
    let tracked_paths = previous
        .artifacts_by_path()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let mut graph_only_paths = Vec::new();
    for artifact in previous.artifacts_by_path() {
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            != kin_core::SourceProjectionDisposition::Materialized
        {
            graph_only_paths.push(artifact.path.clone());
        }
    }
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
    let scan = kin_index::scan_repository_preserving_graph_only(
        working_dir,
        &ignore,
        scanned_tracked.into_iter(),
        graph_only_paths.iter(),
    )
    .map_err(kin_index::IndexError::from)?;
    let mut observed =
        crate::commit_deltas::observed_tree_from_complete_scan(&state.blobs, &scan, &previous)?;
    if let Some(observation) = observation {
        for artifact in previous.artifacts_by_path() {
            if observation_covers_path(observation, &artifact.path) {
                continue;
            }
            observed.insert(artifact.path.clone(), artifact.entry);
        }
        observed.retain(|path, _| previous.artifact_id_at_path(path).is_some());
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
        let _ = publish_exact_workspace_tree(state, &admitted)?;
        // Authority has committed the removal, so the entities derived from
        // those paths go before the graph is asked to match. kin-db refuses a
        // tree transition that leaves an entity on a path the staged tree no
        // longer carries, and it is right to: an artifact that stops existing
        // while its entities keep ranking is the exposure this ordering exists
        // to prevent.
        evict_enrichment_for_removed_paths(state, &deltas)?;
        state.graph.apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: deltas.clone(),
            ..TransactionDelta::default()
        })?;
    }

    Ok(ExactTreeAdmission {
        deltas,
        changed_paths,
        semantic_events: dedup_file_events(semantic_events),
    })
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
    let admission = exact_tree_admission(state, None)?;
    admit_file_event_with_exact_tree(state, event, &admission.changed_paths)
}

fn clear_incompatible_facets(
    state: &DaemonState,
    file_id: &FilePathId,
    keep: EnrichmentFacet,
) -> Result<FacetCleanup> {
    let mut cleanup = FacetCleanup::default();

    if keep != EnrichmentFacet::EntitySource {
        let entities = state.graph.query_entities(&EntityFilter {
            file_path: Some(file_id.clone()),
            ..Default::default()
        })?;
        cleanup.removed_entities = entities.into_iter().map(|entity| entity.id).collect();
        state
            .graph
            .remove_entities_batch(&cleanup.removed_entities)?;
        cleanup.changed |= !cleanup.removed_entities.is_empty();
        if state.graph.get_file_layout(file_id)?.is_some() {
            state.graph.delete_file_layout(file_id)?;
            cleanup.changed = true;
        }
    }

    if keep != EnrichmentFacet::ShallowSyntax && state.graph.get_shallow_file(file_id)?.is_some() {
        state.graph.delete_shallow_file(file_id)?;
        cleanup.changed = true;
    }
    if keep != EnrichmentFacet::StructuredArtifact
        && state.graph.get_structured_artifact(file_id)?.is_some()
    {
        state.graph.delete_structured_artifact(file_id)?;
        cleanup.changed = true;
    }
    if keep != EnrichmentFacet::OpaqueArtifact
        && state.graph.get_opaque_artifact(file_id)?.is_some()
    {
        state.graph.delete_opaque_artifact(file_id)?;
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

/// Remove the enrichment derived from every path a tree transition drops.
///
/// Entities, their relations, and their text and vector index presence are what
/// make a path rankable, and none of it is inferred from the tree: kin-db keeps
/// entity removal an explicit transition and refuses a tree change that would
/// strand one. Clearing here is what lets a removal of any kind, a deleted file
/// or a newly ignored one, take the whole artifact out rather than only its
/// tree entry.
pub(crate) fn evict_enrichment_for_removed_paths(
    state: &DaemonState,
    deltas: &[TreeDelta],
) -> Result<()> {
    for delta in deltas {
        let TreeDelta::Removed { old, .. } = delta else {
            continue;
        };
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

/// Run the reconciliation loop until the cancellation token fires.
///
/// This is the main loop of the daemon. It:
/// 1. Watches the working directory for file changes (via `notify`)
/// 2. Drains batches of events
/// 3. For each event, runs the reconciler (file -> overlay)
/// 4. Projects overlay mutations back to files (overlay -> file)
///
/// The loop runs on a tokio task and shares state through `DaemonState`.
pub async fn run_loop(
    state: Arc<DaemonState>,
    config: LoopConfig,
    cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
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
    let enrichment_pipeline = IndexPipeline::new();

    info!(
        poll_ms = config.poll_interval_ms,
        batch = config.batch_size,
        "reconciliation loop started"
    );

    // Startup deliberately admits nothing. Repository authority is already
    // complete when the daemon opens it, and the working copy is a derived
    // view of that authority. Sweeping the working copy here would publish
    // whatever bytes happen to sit on disk into the repository-v6 workspace
    // before any command runs, so a command that spawned this daemon would
    // observe ambiently ingested content as graph-owned workspace state.
    // Working-copy content crosses the compare-and-swap only through live
    // watcher-observed edits below and through explicit admission seams such
    // as `/commands/commit`. Divergence introduced while no daemon was
    // running stays projection drift until one of those seams admits it.

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
            info!("reconciliation loop shutting down");
            break;
        }

        // The supervisor stopped this loop for spending the machine without
        // admitting anything. Enforced at this checkpoint, before any lock is
        // taken, so nothing is abandoned mid-transaction. Graph truth is
        // untouched and the daemon keeps serving it; what stops is the automatic
        // tracking of working-copy edits, which the announced reason says.
        if pass.halted() {
            state
                .reconciliation_status
                .store(RECON_IDLE, Ordering::Relaxed);
            error!(
                reason = pass.halt_reason().unwrap_or_default(),
                "reconciliation loop stopped by the background-work supervisor"
            );
            break;
        }

        // Sweep under the same cross-surface gate used by registration and
        // graph apply, then record every automatic release durably.
        {
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
                        let _ =
                            state.record_coordination_event(crate::state::CoordinationEventDraft {
                                event: "intent_release",
                                outcome: "expired".to_string(),
                                session_id: Some(intent.session_id.to_string()),
                                intent_id: Some(intent.intent_id.to_string()),
                                intent_ids: vec![intent.intent_id.to_string()],
                                transaction_id: None,
                                scopes: intent
                                    .scopes
                                    .iter()
                                    .map(crate::api::format_scope)
                                    .collect(),
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

        if pending_events.is_empty() {
            // Nothing observed, so this loop is genuinely doing nothing and its
            // working stretch ends. This is the only path that clears it: a tick
            // that keeps retrying the same unadmittable paths never arrives
            // here, which is what makes that spin observable.
            pass.idle();
            // No events — sleep briefly then check again.
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.changed() => {
                    state.reconciliation_status.store(RECON_IDLE, Ordering::Relaxed);
                    info!("reconciliation loop shutting down");
                    break;
                }
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
        let exact_admission = match exact_tree_admission(&state, Some(&observation)) {
            Ok(admission) => admission,
            Err(error) => {
                warn!(
                    error = %error,
                    "complete exact-tree admission failed; retaining graph truth and retrying watcher paths"
                );
                let deferred_at = Instant::now();
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
                    continue;
                }
            };
            if matches!(admitted, AdmittedFileEvent::Ignored) {
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
                AdmittedFileEvent::Ignored => unreachable!(),
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
                AdmittedFileEvent::Ignored => unreachable!(),
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

        tracing::subscriber::with_default(subscriber, || {
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
        });

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
    let exact_admission = exact_tree_admission(state, None)?;
    if exact_admission.deltas.is_empty() {
        drop(graph_mutation);
        return Ok(());
    }
    let events = exact_admission.semantic_events;

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
                continue;
            }
        };
        if matches!(admitted, AdmittedFileEvent::Ignored) {
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
            AdmittedFileEvent::Ignored => unreachable!(),
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
            AdmittedFileEvent::Ignored => unreachable!(),
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
