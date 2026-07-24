// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use chrono::TimeZone;
use kin_blobs::BlobStore;
use kin_model::{
    ArtifactDelta, ArtifactDeltaKind, AuthorId, BranchName, FilePathId, Hash256, SemanticChange,
    SemanticChangeId, SourceEntryKind, Timestamp,
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::error::{GitError, Result};

const MAX_BASE_LINK_ANCHORS: usize = 64;
const MAX_BASE_LINK_TREE_ENTRIES: usize = 100_000;
const MAX_BASE_LINK_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;

fn enforce_base_link_budget(anchors: usize, entries: usize, expanded_bytes: u64) -> Result<()> {
    if anchors > MAX_BASE_LINK_ANCHORS {
        return Err(GitError::Other(format!(
            "truncated Git history requires {anchors} boundary anchors; limit is {MAX_BASE_LINK_ANCHORS}"
        )));
    }
    if entries > MAX_BASE_LINK_TREE_ENTRIES {
        return Err(GitError::Other(format!(
            "truncated Git history boundary contains {entries} source entries; limit is {MAX_BASE_LINK_TREE_ENTRIES}"
        )));
    }
    if expanded_bytes > MAX_BASE_LINK_EXPANDED_BYTES {
        return Err(GitError::Other(format!(
            "truncated Git history boundary contains {expanded_bytes} source bytes; limit is {MAX_BASE_LINK_EXPANDED_BYTES}"
        )));
    }
    Ok(())
}

fn open_repo(path: &Path) -> std::result::Result<gix::Repository, gix::open::Error> {
    let dot_git = path.join(".git");
    if dot_git.is_dir() {
        gix::open(dot_git)
    } else {
        gix::open(path)
    }
}

fn shallow_boundary_ids(repo: &gix::Repository) -> Result<HashSet<gix::ObjectId>> {
    let commits = repo
        .shallow_commits()
        .map_err(|error| GitError::Git(format!("read shallow boundary: {error}")))?;
    Ok(commits
        .as_ref()
        .map(|commits| commits.iter().copied().collect())
        .unwrap_or_default())
}

#[derive(Debug, Clone)]
pub(crate) struct CommitFileDelta {
    pub path: String,
    /// Prior side of the change, if present: its Git object id and class. A file
    /// or symlink carries a blob id; a gitlink carries the pinned commit id.
    pub old: Option<(gix::ObjectId, GitEntryClass)>,
    /// Resulting side of the change, if present: its Git object id and class.
    pub new: Option<(gix::ObjectId, GitEntryClass)>,
}

/// Options for importing Git history into Kin.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Only import HEAD (no history walk). Produces a single SemanticChange
    /// from the current tree state.
    pub shallow: bool,

    /// Maximum number of commits to import (0 = unlimited).
    pub max_commits: usize,

    /// Branch to import from (default: HEAD).
    pub branch: Option<String>,
}

/// A Git commit mapped to Kin's domain before graph insertion.
#[derive(Debug, Clone)]
pub struct ImportedChange {
    /// The SemanticChange ready for graph insertion.
    pub change: SemanticChange,
    /// Original Git commit hash for traceability.
    pub git_oid: String,
}

/// Compute a deterministic SemanticChangeId from a Git commit OID.
///
/// This ensures the same Git commit always maps to the same Kin change ID,
/// making imports idempotent.
fn change_id_from_git_oid(oid: &gix::ObjectId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-git-import-v1:");
    hasher.update(oid.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

fn timestamp_from_git_seconds(seconds: i64, oid: &gix::ObjectId) -> Result<Timestamp> {
    chrono::Utc
        .timestamp_opt(seconds, 0)
        .single()
        .map(Timestamp::from)
        .ok_or_else(|| {
            GitError::Git(format!(
                "Git commit {oid} has author timestamp {seconds} outside Kin's supported range"
            ))
        })
}

/// Compute the deterministic imported SemanticChangeId for a Git commit hash.
pub fn semantic_change_id_from_git_oid_hex(oid_hex: &str) -> Result<SemanticChangeId> {
    let oid = gix::ObjectId::from_hex(oid_hex.as_bytes())
        .map_err(|err| GitError::Git(format!("invalid git oid '{}': {}", oid_hex, err)))?;
    Ok(change_id_from_git_oid(&oid))
}

/// Import Git history from a repository at `repo_path`.
///
/// Returns a list of `ImportedChange` objects in topological order (oldest first).
/// The caller is responsible for:
/// 1. Creating a genesis SemanticChange (from kin-core)
/// 2. Attaching root commits as children of genesis
/// 3. Inserting changes into the graph via GraphStore
///
/// This function does NOT perform entity extraction (that requires kin-parser
/// and kin-index). It creates SemanticChange objects with artifact deltas only.
/// Entity deltas will be populated by the indexing pipeline when it processes
/// the imported changes.
pub fn import_git_history(
    repo_path: &Path,
    genesis_id: SemanticChangeId,
    opts: &ImportOptions,
) -> Result<Vec<ImportedChange>> {
    import_git_history_with_blobs(repo_path, genesis_id, opts, None)
}

/// Import Git history and optionally materialize blobs into a Kin blob store.
pub fn import_git_history_with_blobs(
    repo_path: &Path,
    genesis_id: SemanticChangeId,
    opts: &ImportOptions,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let _span = tracing::info_span!(
        "kin.git.import_history",
        repo = %repo_path.display(),
        shallow = opts.shallow,
        max_commits = opts.max_commits,
        has_branch = opts.branch.is_some(),
        blobs = blob_store.is_some()
    )
    .entered();
    let repo = open_repo(repo_path).map_err(|e| GitError::Git(e.to_string()))?;

    // Find the starting commit.
    let head_ref = if let Some(branch) = &opts.branch {
        repo.find_reference(&format!("refs/heads/{branch}"))
            .map_err(|e| GitError::BranchNotFound(format!("{branch}: {e}")))?
    } else {
        repo.head_ref()
            .map_err(|e| GitError::Git(e.to_string()))?
            .ok_or(GitError::EmptyRepository)?
    };

    let head_id = head_ref.id().detach();

    if opts.shallow {
        return import_shallow(&repo, head_id, genesis_id, blob_store);
    }

    import_full(&repo, head_id, genesis_id, opts.max_commits, blob_store)
}

/// Import the ancestry reachable from a specific Git commit.
pub fn import_git_history_to_commit_with_blobs(
    repo_path: &Path,
    git_oid_hex: &str,
    genesis_id: SemanticChangeId,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let _span = tracing::info_span!(
        "kin.git.import_history_to_commit",
        repo = %repo_path.display(),
        git_oid = %git_oid_hex,
        blobs = blob_store.is_some()
    )
    .entered();
    let repo = open_repo(repo_path).map_err(|e| GitError::Git(e.to_string()))?;
    let target_id = gix::ObjectId::from_hex(git_oid_hex.as_bytes())
        .map_err(|err| GitError::Git(format!("invalid git oid '{}': {}", git_oid_hex, err)))?;
    repo.find_commit(target_id)
        .map_err(|e| GitError::CommitNotFound(format!("{git_oid_hex}: {e}")))?;
    import_full(&repo, target_id, genesis_id, 0, blob_store)
}

/// Cheap, Git-native ancestry check: is `ancestor_oid_hex` reachable by
/// walking parents from `descendant_oid_hex`? This is the same DAG
/// relationship `git merge-base --is-ancestor` reports. The walk visits only
/// commit objects — no trees, blobs, or diffing — so it costs a fraction of
/// a full history import with semantic enrichment, and callers can use it to
/// decide whether that expensive import is even worth starting.
///
/// Returns `None` when the question cannot be answered cheaply: either oid
/// fails to parse, either commit is absent from the repository's object
/// database, or the repository cannot be opened at `repo_path`. Callers
/// should treat `None` as "unknown" and fall back to their normal resolve
/// path rather than treating it as a negative answer.
pub fn is_ancestor_commit(
    repo_path: &Path,
    ancestor_oid_hex: &str,
    descendant_oid_hex: &str,
) -> Option<bool> {
    let repo = open_repo(repo_path).ok()?;
    let ancestor_id = gix::ObjectId::from_hex(ancestor_oid_hex.as_bytes()).ok()?;
    let descendant_id = gix::ObjectId::from_hex(descendant_oid_hex.as_bytes()).ok()?;
    repo.find_commit(ancestor_id).ok()?;
    repo.find_commit(descendant_id).ok()?;

    if ancestor_id == descendant_id {
        return Some(true);
    }

    let walk = repo.rev_walk([descendant_id]).all().ok()?;
    for step in walk {
        let info = step.ok()?;
        if info.id().detach() == ancestor_id {
            return Some(true);
        }
    }
    Some(false)
}

/// Outcome of expanding an abbreviated Git commit hash against the object
/// database of the repository at `repo_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitOidPrefixExpansion {
    /// Exactly one object matches the prefix and it is a commit; carries the
    /// full 40-character hex id.
    Commit(String),
    /// More than one object in the repository shares the prefix.
    Ambiguous,
    /// No object matches, the unique match is not a commit, or the
    /// repository/prefix cannot be inspected at all.
    NotFound,
}

/// Expand an abbreviated (4–39 hex character) Git commit hash to its full id.
///
/// Only the Git object database is consulted for the expansion; whether the
/// expanded commit exists as imported semantic history stays the caller's
/// decision, so graph authority over history is unchanged. Repository-open
/// and prefix-parse failures report as `NotFound` — callers treat that
/// exactly like an unknown ref.
pub fn expand_git_commit_prefix(repo_path: &Path, prefix_hex: &str) -> GitOidPrefixExpansion {
    let Ok(repo) = open_repo(repo_path) else {
        return GitOidPrefixExpansion::NotFound;
    };
    let Ok(prefix) = gix::hash::Prefix::from_hex(prefix_hex) else {
        return GitOidPrefixExpansion::NotFound;
    };
    match repo.objects.lookup_prefix(prefix, None) {
        Ok(Some(Ok(id))) => {
            if repo.find_commit(id).is_ok() {
                GitOidPrefixExpansion::Commit(id.to_string())
            } else {
                GitOidPrefixExpansion::NotFound
            }
        }
        Ok(Some(Err(()))) => GitOidPrefixExpansion::Ambiguous,
        _ => GitOidPrefixExpansion::NotFound,
    }
}

/// Shallow import: create a single SemanticChange from HEAD's tree.
fn import_shallow(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    genesis_id: SemanticChangeId,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let _span = tracing::info_span!(
        "kin.git.import_shallow",
        head = %head_id,
        blobs = blob_store.is_some()
    )
    .entered();
    let commit = repo
        .find_commit(head_id)
        .map_err(|e| GitError::CommitNotFound(format!("{head_id}: {e}")))?;

    let change = commit_to_change(repo, &commit, genesis_id, true, blob_store)?;
    let oid_str = head_id.to_string();

    info!(git_oid = %oid_str, kin_id = %change.id, "shallow import from HEAD");

    Ok(vec![ImportedChange {
        change,
        git_oid: oid_str,
    }])
}

/// Order a selected commit set so every in-set parent precedes its children.
///
/// Oid order is only a deterministic tie-break between commits whose selected
/// parents have already been emitted. It must never override Git ancestry.
fn order_selected_oids_parent_first(
    repo: &gix::Repository,
    selected: Vec<gix::ObjectId>,
) -> Result<Vec<gix::ObjectId>> {
    let selected_set: HashSet<gix::ObjectId> = selected.iter().copied().collect();
    if selected_set.len() != selected.len() {
        return Err(GitError::Git(
            "history walk returned a duplicate commit id".to_string(),
        ));
    }

    let mut indegree: HashMap<gix::ObjectId, usize> =
        selected.iter().copied().map(|oid| (oid, 0)).collect();
    let mut children: BTreeMap<gix::ObjectId, BTreeSet<gix::ObjectId>> = BTreeMap::new();

    for &oid in &selected {
        let commit = repo
            .find_object(oid)
            .map_err(|err| GitError::Git(err.to_string()))?
            .into_commit();
        let selected_parents: BTreeSet<gix::ObjectId> = commit
            .parent_ids()
            .map(|parent| parent.detach())
            .filter(|parent| selected_set.contains(parent))
            .collect();

        *indegree
            .get_mut(&oid)
            .expect("every selected oid has an indegree entry") = selected_parents.len();
        for parent in selected_parents {
            children.entry(parent).or_default().insert(oid);
        }
    }

    let mut ready: BTreeSet<gix::ObjectId> = indegree
        .iter()
        .filter_map(|(oid, degree)| (*degree == 0).then_some(*oid))
        .collect();
    let mut ordered = Vec::with_capacity(selected.len());

    while let Some(oid) = ready.iter().next().copied() {
        ready.remove(&oid);
        ordered.push(oid);

        if let Some(commit_children) = children.get(&oid) {
            for &child in commit_children {
                let degree = indegree
                    .get_mut(&child)
                    .expect("every selected child has an indegree entry");
                *degree = degree
                    .checked_sub(1)
                    .expect("selected commit indegree cannot underflow");
                if *degree == 0 {
                    ready.insert(child);
                }
            }
        }
    }

    if ordered.len() != selected.len() {
        return Err(GitError::Git(
            "selected Git history is not an acyclic parent graph".to_string(),
        ));
    }

    Ok(ordered)
}

/// Select a deterministic, ancestry-connected history window rooted at HEAD.
///
/// Sorting the entire walk by `(time desc, oid asc)` before truncation can drop
/// HEAD when an equal-timestamp tie straddles the limit. It can also select an
/// ancestor while omitting the commits that connect it to HEAD, leaving the
/// imported branch head pointed at the wrong change or carrying unreachable
/// history. Instead, expand only parents of commits already selected, choosing
/// the newest frontier parent (oid as the tie-break) each time. The result is
/// input-order independent, always contains HEAD for a non-empty limit, and is
/// connected through Git parent edges. Emission order is imposed separately by
/// [`order_selected_oids_parent_first`].
pub(crate) fn select_history_oids_from_head(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    timed: Vec<(i64, gix::ObjectId)>,
    max_commits: usize,
) -> Result<Vec<gix::ObjectId>> {
    let mut commit_times = HashMap::with_capacity(timed.len());
    for (commit_time, oid) in timed {
        if commit_times.insert(oid, commit_time).is_some() {
            return Err(GitError::Git(
                "history walk returned a duplicate commit id".to_string(),
            ));
        }
    }
    let head_time = commit_times.get(&head_id).copied().ok_or_else(|| {
        GitError::Git("history walk did not contain the requested head commit".to_string())
    })?;

    // Unlimited import already contains the entire reachable ancestry, so it
    // needs no frontier expansion (and no second object lookup per commit).
    // Keep a deterministic child-first order for co-change consumers; semantic
    // history imposes parent-first emission in the following phase.
    if max_commits == 0 {
        let mut all: Vec<_> = commit_times
            .into_iter()
            .map(|(oid, commit_time)| (Reverse(commit_time), oid))
            .collect();
        all.sort_unstable();
        return Ok(all.into_iter().map(|(_, oid)| oid).collect());
    }

    let mut frontier = BTreeSet::from([(Reverse(head_time), head_id)]);
    let mut selected = Vec::with_capacity(max_commits.min(commit_times.len()));
    let mut selected_set = HashSet::new();

    while selected.len() < max_commits {
        let Some(candidate) = frontier.iter().next().copied() else {
            break;
        };
        frontier.remove(&candidate);
        let oid = candidate.1;
        if !selected_set.insert(oid) {
            continue;
        }
        selected.push(oid);

        let commit = repo
            .find_object(oid)
            .map_err(|err| GitError::Git(err.to_string()))?
            .into_commit();
        for parent in commit.parent_ids().map(|parent| parent.detach()) {
            if selected_set.contains(&parent) {
                continue;
            }
            if let Some(parent_time) = commit_times.get(&parent).copied() {
                frontier.insert((Reverse(parent_time), parent));
            }
        }
    }

    Ok(selected)
}

/// Select a deterministic HEAD-rooted history window without first walking or
/// retaining the repository's full reachable history. Only selected commits
/// and their immediate frontier parents are inspected.
pub(crate) fn select_bounded_history_oids_from_head(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    max_commits: usize,
) -> Result<Vec<gix::ObjectId>> {
    debug_assert!(max_commits > 0);
    let commit_time = |oid: gix::ObjectId| -> Result<i64> {
        repo.find_commit(oid)
            .map_err(|error| GitError::CommitNotFound(format!("{oid}: {error}")))?
            .time()
            .map(|time| time.seconds)
            .map_err(|error| GitError::Git(error.to_string()))
    };
    let shallow_boundaries = shallow_boundary_ids(repo)?;
    let mut frontier = BTreeSet::from([(Reverse(commit_time(head_id)?), head_id)]);
    let mut selected = Vec::with_capacity(max_commits);
    let mut selected_set = HashSet::new();

    while selected.len() < max_commits {
        let Some(candidate) = frontier.iter().next().copied() else {
            break;
        };
        frontier.remove(&candidate);
        let oid = candidate.1;
        if !selected_set.insert(oid) {
            continue;
        }
        selected.push(oid);
        if selected.len() == max_commits {
            break;
        }
        if shallow_boundaries.contains(&oid) {
            continue;
        }

        let commit = repo
            .find_commit(oid)
            .map_err(|error| GitError::CommitNotFound(format!("{oid}: {error}")))?;
        for parent in commit.parent_ids().map(|parent| parent.detach()) {
            if selected_set.contains(&parent)
                || frontier.iter().any(|(_, candidate)| *candidate == parent)
            {
                continue;
            }
            frontier.insert((Reverse(commit_time(parent)?), parent));
        }
    }
    Ok(selected)
}

/// Full history import: walk commits in deterministic topological order.
fn import_full(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    genesis_id: SemanticChangeId,
    max_commits: usize,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let _span = tracing::info_span!(
        "kin.git.import_full",
        head = %head_id,
        max_commits = max_commits,
        blobs = blob_store.is_some()
    )
    .entered();

    // Phase 1: bounded mode expands a deterministic ancestry-connected window
    // directly from HEAD; unlimited mode collects the complete walk. Selection
    // order is not emission order: once the set is fixed, a deterministic Kahn
    // pass emits every selected parent before its selected children, using oid
    // order only among simultaneously ready nodes.
    let oids: Vec<gix::ObjectId> = if max_commits > 0 {
        let selected = select_bounded_history_oids_from_head(repo, head_id, max_commits)?;
        order_selected_oids_parent_first(repo, selected)?
    } else {
        let _span = tracing::info_span!("kin.git.import_full.collect_oids").entered();
        let walk = repo
            .rev_walk([head_id])
            .sorting(gix::revision::walk::Sorting::ByCommitTime(
                Default::default(),
            ))
            .all()
            .map_err(|e| GitError::Git(e.to_string()))?;
        let timed: Vec<(i64, gix::ObjectId)> = walk
            .map(|r| {
                r.map(|info| (info.commit_time.unwrap_or(0), info.id().detach()))
                    .map_err(|e| GitError::Git(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let selected = select_history_oids_from_head(repo, head_id, timed, max_commits)?;
        order_selected_oids_parent_first(repo, selected)?
    };
    let shallow_boundaries = shallow_boundary_ids(repo)?;

    // Phase 2: map each commit to an ImportedChange in parallel. Each commit's
    // mapping is independent (deterministic change_id from its OID, parents from
    // its parent OIDs, all fields derived purely from the commit); the only
    // shared side-effect is the content-addressed blob_store.write, which is
    // thread-safe and idempotent by hash. rayon's indexed `par_iter().collect()`
    // preserves `oids` order, so the result is byte-identical to a serial walk.
    let mut changes: Vec<ImportedChange> = {
        let _span =
            tracing::info_span!("kin.git.import_full.map_commits", commits = oids.len()).entered();
        let thread_safe = repo.clone().into_sync();

        // Force every pack index to load once here, on the walking thread,
        // before the workers fan out. gitoxide loads pack indices lazily on
        // first access; when many rayon workers take that first look
        // concurrently through their own thread-local handles, a worker can
        // transiently observe a present object as missing while another worker
        // is still initializing the shared index slot. Loading all indices up
        // front on a single thread closes that window for the commit lookup
        // and every nested tree/blob lookup below. A genuinely absent object
        // still fails loud in the worker.
        thread_safe
            .to_thread_local()
            .objects
            .packed_object_count()
            .map_err(|e| GitError::Git(e.to_string()))?;

        oids.par_iter()
            .map(|oid| {
                let local = thread_safe.to_thread_local();
                // Object lookups can transiently miss while another worker is
                // still initializing a shared object-database slot (the loose-
                // object analogue of the pack-index window pre-warmed above), so
                // a miss is retried once before it is treated as genuinely
                // absent and fails loud.
                let commit = match local.find_object(*oid) {
                    Ok(object) => object,
                    Err(_) => local
                        .find_object(*oid)
                        .map_err(|e| GitError::Git(e.to_string()))?,
                }
                .into_commit();
                let is_root = commit.parent_ids().count() == 0 || shallow_boundaries.contains(oid);
                let change = commit_to_change(&local, &commit, genesis_id, is_root, blob_store)?;
                let oid_str = oid.to_string();
                debug!(git_oid = %oid_str, kin_id = %change.id, parents = change.parents.len(), "imported commit");
                Ok(ImportedChange {
                    change,
                    git_oid: oid_str,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };

    // Close the DAG at the truncation horizon before emitting (see the helper).
    close_truncated_history_dag(&mut changes, genesis_id);

    info!(count = changes.len(), "full history import complete");
    Ok(changes)
}

/// Serial counterpart of [`import_full`], retained as the byte-identical
/// reference for the parallel commit-mapping path.
#[cfg(test)]
fn import_full_serial(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    genesis_id: SemanticChangeId,
    max_commits: usize,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let mut changes = Vec::new();
    let walk = repo
        .rev_walk([head_id])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(|e| GitError::Git(e.to_string()))?;

    // Same deterministic selection and parent-first ordering as `import_full`,
    // so the serial reference stays byte-identical to the parallel path under
    // equal-timestamp ties and `max_commits` truncation.
    let timed: Vec<(i64, gix::ObjectId)> = walk
        .map(|r| {
            r.map(|info| (info.commit_time.unwrap_or(0), info.id().detach()))
                .map_err(|e| GitError::Git(e.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    let selected = select_history_oids_from_head(repo, head_id, timed, max_commits)?;
    let oids = order_selected_oids_parent_first(repo, selected)?;
    let shallow_boundaries = shallow_boundary_ids(repo)?;

    for oid in &oids {
        let commit = repo
            .find_object(*oid)
            .map_err(|e| GitError::Git(e.to_string()))?
            .into_commit();
        let is_root = commit.parent_ids().count() == 0 || shallow_boundaries.contains(oid);
        let change = commit_to_change(repo, &commit, genesis_id, is_root, blob_store)?;
        changes.push(ImportedChange {
            change,
            git_oid: oid.to_string(),
        });
    }

    close_truncated_history_dag(&mut changes, genesis_id);

    Ok(changes)
}

/// Re-point dangling boundary parents at `genesis_id` so a truncated import is a
/// self-contained DAG.
///
/// `max_commits` truncation keeps only the newest commits, so the oldest kept
/// commit's Git parents can fall outside the imported set. `commit_to_change`
/// derives every non-root commit's parents from its Git parent OIDs regardless
/// of whether those parents were selected, so a truncated import emits changes
/// whose parent ids were never inserted into the graph. A later ancestry walk
/// (`kin_core::collect_changes_at_ref`, used by ref-scoped locate/log/blame)
/// then fails "change <id> not found" the moment it reaches that dangling
/// edge — 500ing `locate --ref git:<oid>` even for HEAD, because HEAD's own
/// history walk crosses the horizon.
///
/// Re-pointing every parent that was not imported to `genesis_id` closes the DAG
/// at the import horizon — the same shape a true root commit already has — so
/// every parent reference resolves within the imported set ∪ {genesis}. A full
/// import (`max_commits == 0`) walks the entire ancestry, so no parent is ever
/// missing and this is a no-op; it only rewrites the boundary of a truncated
/// window. The rewrite depends solely on the imported id set and `genesis_id`
/// and preserves parent order (dedup keeps the first occurrence), so the
/// parallel and serial import paths stay byte-identical.
fn close_truncated_history_dag(changes: &mut [ImportedChange], genesis_id: SemanticChangeId) {
    let imported: HashSet<SemanticChangeId> = changes.iter().map(|ic| ic.change.id).collect();
    for ic in changes.iter_mut() {
        let original = std::mem::take(&mut ic.change.parents);
        let mut seen = HashSet::new();
        let mut rewritten = Vec::with_capacity(original.len());
        for parent in original {
            let resolved = if parent == genesis_id || imported.contains(&parent) {
                parent
            } else {
                genesis_id
            };
            if seen.insert(resolved) {
                rewritten.push(resolved);
            }
        }
        ic.change.parents = rewritten;
    }
}

/// Convert a gitoxide commit into a SemanticChange.
///
/// Root commits (no Git parents) are attached to the genesis change.
/// Non-root commits reference their Git parents via deterministic ID mapping.
fn commit_to_change(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
    genesis_id: SemanticChangeId,
    is_root: bool,
    blob_store: Option<&BlobStore>,
) -> Result<SemanticChange> {
    let oid = commit.id;
    let change_id = change_id_from_git_oid(&oid);

    // Map parents: root commits → [genesis_id], others → mapped parent IDs.
    let parents = if is_root {
        vec![genesis_id]
    } else {
        commit
            .parent_ids()
            .map(|pid| change_id_from_git_oid(&pid.detach()))
            .collect()
    };

    // Extract author info.
    let author_sig = commit.author().map_err(|e| GitError::Git(e.to_string()))?;
    let author_name = author_sig.name.to_string();
    let author_email = author_sig.email.to_string();
    let author = AuthorId::new(format!("{author_name} <{author_email}>"));

    // Extract timestamp.
    let git_time = author_sig
        .time()
        .map_err(|e| GitError::Git(e.to_string()))?;
    let timestamp = timestamp_from_git_seconds(git_time.seconds, &oid)?;

    // Extract commit message.
    let message = commit
        .message_raw()
        .map_err(|e| GitError::Git(e.to_string()))?
        .to_string();

    // A synthetic import root (shallow import or a real Git root) must carry
    // the complete tree. A merge must also carry a full correction relative
    // to the union of all direct-parent trees: semantic history replays the
    // complete DAG, while a Git merge diff against only its first parent can
    // otherwise leak second-parent content that the merge did not select.
    let artifact_deltas = if is_root {
        extract_full_tree_artifact_deltas(repo, commit, blob_store)?
    } else if commit.parent_ids().count() > 1 {
        extract_merge_artifact_deltas(repo, commit, blob_store)?
    } else {
        extract_artifact_deltas(repo, commit, blob_store)?
    };

    let authored_on = if is_root {
        Some(BranchName::new("main"))
    } else {
        None
    };

    Ok(SemanticChange {
        id: change_id,
        parents,
        timestamp,
        author,
        message,
        entity_deltas: vec![],   // Populated by indexing pipeline
        relation_deltas: vec![], // Populated by indexing pipeline
        artifact_deltas,
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on,
    })
}

/// Importer-internal classification of a Git tree entry.
///
/// Distinct from the canonical [`SourceEntryKind`] so a submodule pointer can be
/// carried through import as a tracked, mode-unknown change without adding a
/// Git-compatibility construct to the shared type vocabulary. A gitlink is not
/// exact-source materializable (it names another repository's commit, not file
/// content), so it resolves to a source-tree gap rather than a synthesized file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitEntryClass {
    /// A file or symbolic link — an exact source entry with a known mode.
    Source(SourceEntryKind),
    /// A gitlink (submodule pointer). Recorded as a mode-unknown artifact delta;
    /// its pinned commit id is captured as the delta's content identity.
    Gitlink,
}

/// Classify a Git tree entry mode. `None` for a tree (directory), which is not a
/// source entry.
///
/// A gitlink is classified, not refused: it is recorded as a tracked,
/// mode-unknown pointer change so a submodule move is visible to review and the
/// presence of a submodule anywhere in history does not block ref hydration.
fn classify_git_entry(mode: gix::objs::tree::EntryMode) -> Option<GitEntryClass> {
    use gix::objs::tree::EntryKind;

    match mode.kind() {
        EntryKind::Blob => Some(GitEntryClass::Source(SourceEntryKind::File {
            executable: false,
        })),
        EntryKind::BlobExecutable => Some(GitEntryClass::Source(SourceEntryKind::File {
            executable: true,
        })),
        EntryKind::Link => Some(GitEntryClass::Source(SourceEntryKind::Symlink)),
        EntryKind::Tree => None,
        EntryKind::Commit => Some(GitEntryClass::Gitlink),
    }
}

/// Content-identity hash for one side of an artifact delta. A file or symlink
/// hashes its Git blob; a gitlink hashes the textual pointer form Git itself
/// uses in diffs (`Subproject commit <hex>`), so a pointer move is a visible
/// content change and the pinned commit stays recoverable from the blob store.
fn entry_content_hash(
    repo: &gix::Repository,
    oid: gix::ObjectId,
    class: GitEntryClass,
    blob_store: Option<&BlobStore>,
) -> Result<Hash256> {
    match class {
        GitEntryClass::Source(_) => blob_hash(repo, oid, blob_store),
        GitEntryClass::Gitlink => gitlink_pointer_hash(oid, blob_store),
    }
}

fn gitlink_pointer_hash(oid: gix::ObjectId, blob_store: Option<&BlobStore>) -> Result<Hash256> {
    let content = format!("Subproject commit {oid}\n").into_bytes();
    if let Some(store) = blob_store {
        store.write(&content)?;
    }
    Ok(Hash256::from_bytes(kin_blobs::digest(&content).0))
}

fn utf8_git_path(path: &[u8]) -> Result<String> {
    std::str::from_utf8(path).map(str::to_owned).map_err(|_| {
        GitError::Other(
            "exact Git import encountered a non-UTF-8 path; import refused rather than recording a lossy source identity"
                .to_string(),
        )
    })
}

fn added_artifact_kind(kind: SourceEntryKind) -> ArtifactDeltaKind {
    match kind {
        SourceEntryKind::File { executable: false } => ArtifactDeltaKind::AddedRegularFile,
        SourceEntryKind::File { executable: true } => ArtifactDeltaKind::AddedExecutableFile,
        SourceEntryKind::Symlink => ArtifactDeltaKind::AddedSymlink,
    }
}

fn modified_artifact_kind(kind: SourceEntryKind) -> ArtifactDeltaKind {
    match kind {
        SourceEntryKind::File { executable: false } => ArtifactDeltaKind::ModifiedRegularFile,
        SourceEntryKind::File { executable: true } => ArtifactDeltaKind::ModifiedExecutableFile,
        SourceEntryKind::Symlink => ArtifactDeltaKind::ModifiedSymlink,
    }
}

/// Resulting delta kind for an added entry. A gitlink has no exact file mode, so
/// it is recorded as a mode-unknown addition rather than a fabricated file kind.
fn added_delta_kind(class: GitEntryClass) -> ArtifactDeltaKind {
    match class {
        GitEntryClass::Source(kind) => added_artifact_kind(kind),
        GitEntryClass::Gitlink => ArtifactDeltaKind::Added,
    }
}

/// Resulting delta kind for a modified entry. A gitlink pointer move is recorded
/// as a mode-unknown modification.
fn modified_delta_kind(class: GitEntryClass) -> ArtifactDeltaKind {
    match class {
        GitEntryClass::Source(kind) => modified_artifact_kind(kind),
        GitEntryClass::Gitlink => ArtifactDeltaKind::Modified,
    }
}

fn extract_artifact_deltas(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ArtifactDelta>> {
    let mut deltas = Vec::new();
    for delta in commit_file_deltas(repo, commit)? {
        let kind = match (&delta.old, &delta.new) {
            (None, Some((_, class))) => added_delta_kind(*class),
            (Some(_), None) => ArtifactDeltaKind::Removed,
            (Some(_), Some((_, class))) => modified_delta_kind(*class),
            (None, None) => continue,
        };

        let old_hash = delta
            .old
            .map(|(oid, class)| entry_content_hash(repo, oid, class, blob_store))
            .transpose()?;
        let new_hash = delta
            .new
            .map(|(oid, class)| entry_content_hash(repo, oid, class, blob_store))
            .transpose()?;

        deltas.push(ArtifactDelta {
            file_id: FilePathId::new(delta.path),
            kind,
            old_hash,
            new_hash,
        });
    }

    Ok(deltas)
}

fn extract_full_tree_artifact_deltas(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ArtifactDelta>> {
    let tree = commit
        .tree()
        .map_err(|error| GitError::Git(error.to_string()))?;
    full_tree_blob_entries(repo, &tree)?
        .into_iter()
        .map(|(path, oid, class)| {
            Ok(ArtifactDelta {
                file_id: FilePathId::new(path),
                kind: added_delta_kind(class),
                old_hash: None,
                new_hash: Some(entry_content_hash(repo, oid, class, blob_store)?),
            })
        })
        .collect()
}

/// Encode a merge as a complete correction over the union of its direct
/// parent trees. This makes the semantic DAG replay converge on the exact Git
/// merge tree regardless of sibling topological order.
fn extract_merge_artifact_deltas(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ArtifactDelta>> {
    let current_tree = commit
        .tree()
        .map_err(|error| GitError::Git(error.to_string()))?;
    let current: BTreeMap<String, (gix::ObjectId, GitEntryClass)> =
        full_tree_blob_entries(repo, &current_tree)?
            .into_iter()
            .map(|(path, id, class)| (path, (id, class)))
            .collect();

    // Parent order is Git-authoritative. Keep the first occurrence of a path
    // only to provide deterministic old_hash metadata; replay correctness is
    // supplied by the complete remove/upsert correction below.
    let mut parent_union: BTreeMap<String, (gix::ObjectId, GitEntryClass)> = BTreeMap::new();
    for parent_id in commit.parent_ids() {
        let parent = repo
            .find_commit(parent_id.detach())
            .map_err(|error| GitError::Git(error.to_string()))?;
        let parent_tree = parent
            .tree()
            .map_err(|error| GitError::Git(error.to_string()))?;
        for (path, id, class) in full_tree_blob_entries(repo, &parent_tree)? {
            parent_union.entry(path).or_insert((id, class));
        }
    }

    let mut deltas = Vec::with_capacity(current.len() + parent_union.len());
    for (path, (old_id, old_class)) in &parent_union {
        if !current.contains_key(path) {
            deltas.push(ArtifactDelta {
                file_id: FilePathId::new(path),
                kind: ArtifactDeltaKind::Removed,
                old_hash: Some(entry_content_hash(repo, *old_id, *old_class, blob_store)?),
                new_hash: None,
            });
        }
    }
    for (path, (new_id, new_class)) in current {
        let old_hash = parent_union
            .get(&path)
            .map(|(old_id, old_class)| entry_content_hash(repo, *old_id, *old_class, blob_store))
            .transpose()?;
        deltas.push(ArtifactDelta {
            file_id: FilePathId::new(path),
            kind: if old_hash.is_some() {
                modified_delta_kind(new_class)
            } else {
                added_delta_kind(new_class)
            },
            old_hash,
            new_hash: Some(entry_content_hash(repo, new_id, new_class, blob_store)?),
        });
    }
    deltas.sort_by(|left, right| left.file_id.0.cmp(&right.file_id.0));
    Ok(deltas)
}

pub(crate) fn commit_file_deltas(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
) -> Result<Vec<CommitFileDelta>> {
    let tree = commit.tree().map_err(|e| GitError::Git(e.to_string()))?;
    let parent_tree = commit
        .parent_ids()
        .next()
        .map(|parent_id| {
            repo.find_commit(parent_id.detach())
                .map_err(|e| GitError::Git(e.to_string()))?
                .tree()
                .map_err(|e| GitError::Git(e.to_string()))
        })
        .transpose()?;
    let options = gix::diff::Options::default().with_rewrites(None);
    let changes = repo
        .diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(options))
        .map_err(|e| GitError::Git(e.to_string()))?;

    let mut deltas = Vec::new();
    for change in changes {
        match change {
            gix::object::tree::diff::ChangeDetached::Addition {
                location,
                entry_mode,
                id,
                ..
            } => {
                let path = utf8_git_path(location.as_ref())?;
                if let Some(class) = classify_git_entry(entry_mode) {
                    deltas.push(CommitFileDelta {
                        path,
                        old: None,
                        new: Some((id, class)),
                    });
                }
            }
            gix::object::tree::diff::ChangeDetached::Deletion {
                location,
                entry_mode,
                id,
                ..
            } => {
                let path = utf8_git_path(location.as_ref())?;
                if let Some(class) = classify_git_entry(entry_mode) {
                    deltas.push(CommitFileDelta {
                        path,
                        old: Some((id, class)),
                        new: None,
                    });
                }
            }
            gix::object::tree::diff::ChangeDetached::Modification {
                location,
                previous_entry_mode,
                previous_id,
                entry_mode,
                id,
            } => {
                let path = utf8_git_path(location.as_ref())?;
                let old = classify_git_entry(previous_entry_mode).map(|class| (previous_id, class));
                let new = classify_git_entry(entry_mode).map(|class| (id, class));
                if old.is_some() || new.is_some() {
                    deltas.push(CommitFileDelta { path, old, new });
                }
            }
            _ => {}
        }
    }

    Ok(deltas)
}

fn blob_hash(
    repo: &gix::Repository,
    blob_id: gix::ObjectId,
    blob_store: Option<&BlobStore>,
) -> Result<Hash256> {
    let mut blob = repo
        .find_blob(blob_id)
        .map_err(|e| GitError::Git(e.to_string()))?;
    let content = blob.take_data();
    if let Some(store) = blob_store {
        store.write(&content)?;
    }
    Ok(Hash256::from_bytes(kin_blobs::digest(&content).0))
}

/// Deterministic id for the synthetic base-link change, derived from the import
/// window base's first-parent Git OID.
///
/// A domain prefix distinct from `change_id_from_git_oid`'s keeps this id from
/// ever colliding with a real imported commit's id — even if a later, wider
/// import window brings that parent commit in-set and imports it directly.
fn base_link_change_id_from_git_oid(oid: &gix::ObjectId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-git-base-link-v1:");
    hasher.update(oid.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

/// Recompute the deterministic synthetic base-link ID used by pre-0.3
/// truncated imports. This is exposed only so an owning graph migration can
/// recognize and replace that exact historical parent substitution when it
/// widens the import to canonical full ancestry.
pub fn base_link_change_id_from_git_oid_hex(oid: &str) -> Result<SemanticChangeId> {
    let oid = gix::ObjectId::from_hex(oid.as_bytes())
        .map_err(|error| GitError::Git(format!("invalid git oid '{oid}': {error}")))?;
    Ok(base_link_change_id_from_git_oid(&oid))
}

/// Enumerate every source entry in a tree as `(path, blob_oid, kind)`, sorted
/// by path.
///
/// Implemented as a diff of the tree against the empty tree (`None`), which
/// yields one Addition per blob — the same machinery `commit_file_deltas` uses
/// for a root commit. The explicit path sort makes the output a pure, stable
/// function of the tree's content, independent of traversal order.
fn full_tree_blob_entries(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
) -> Result<Vec<(String, gix::ObjectId, GitEntryClass)>> {
    let options = gix::diff::Options::default().with_rewrites(None);
    let changes = repo
        .diff_tree_to_tree(None, Some(tree), Some(options))
        .map_err(|e| GitError::Git(e.to_string()))?;

    let mut entries = Vec::new();
    for change in changes {
        if let gix::object::tree::diff::ChangeDetached::Addition {
            location,
            entry_mode,
            id,
            ..
        } = change
        {
            let path = utf8_git_path(location.as_ref())?;
            if let Some(class) = classify_git_entry(entry_mode) {
                entries.push((path, id, class));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

/// Enumerate at most `max_entries` source entries without first materializing
/// the complete tree diff. This is used at the truncated-history boundary,
/// where an adversarial or unexpectedly large parent tree must fail before its
/// full path set is retained in memory.
fn bounded_full_tree_blob_entries(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    max_entries: usize,
) -> Result<Vec<(String, gix::ObjectId, SourceEntryKind)>> {
    // Returns only exact-source (file/symlink) entries. A gitlink in a
    // truncated-history boundary tree is left as an exact-source gap here rather
    // than routed through the byte-budget blob-load path below; its pointer
    // moves are still recorded by the per-commit diff path.
    let empty_tree = repo.empty_tree();
    let mut changes = empty_tree
        .changes()
        .map_err(|error| GitError::Git(error.to_string()))?;
    changes.options(|options| {
        options.track_rewrites(None);
    });

    let mut entries = Vec::with_capacity(max_entries.min(4_096));
    let mut callback_error = None;
    let mut over_limit = false;
    let traversal_result = changes.for_each_to_obtain_tree(tree, |change| {
        if let gix::object::tree::diff::Change::Addition {
            location,
            entry_mode,
            id,
            ..
        } = change
        {
            let path = match utf8_git_path(location) {
                Ok(path) => path,
                Err(error) => {
                    callback_error = Some(error);
                    return Ok::<_, std::convert::Infallible>(std::ops::ControlFlow::Break(()));
                }
            };
            let kind = match classify_git_entry(entry_mode) {
                Some(GitEntryClass::Source(kind)) => kind,
                // Gitlink (see the fn-level note) and directories are not
                // exact-source entries at this boundary; skip.
                Some(GitEntryClass::Gitlink) | None => {
                    return Ok(std::ops::ControlFlow::Continue(()))
                }
            };
            if entries.len() == max_entries {
                over_limit = true;
                return Ok(std::ops::ControlFlow::Break(()));
            }
            entries.push((path, id.detach(), kind));
        }
        Ok(std::ops::ControlFlow::Continue(()))
    });

    if let Some(error) = callback_error {
        return Err(error);
    }
    if over_limit {
        return Err(GitError::Other(format!(
            "truncated Git history boundary exceeds the remaining source-entry budget of {max_entries}"
        )));
    }
    traversal_result.map_err(|error| GitError::Git(error.to_string()))?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

/// Anchor every omitted parent edge in a truncated import at a synthetic
/// "base-link" change carrying that parent's FULL file universe.
///
/// # Why
///
/// `import_git_history_*` diffs every commit against its first parent, so a
/// truncated window (`--git-history recent`, default 50 commits) records only
/// the files each windowed commit *touched*. The oldest kept commit's own
/// artifact deltas therefore cover just its changed files, never the whole tree
/// it was built on. Semantic enrichment then links each commit against that
/// touched-files-only universe, so a cross-file inbound edge whose *consumer*
/// lives in a file untouched anywhere inside the window is never committed into
/// any imported change — it exists only in live adjacency and the genesis
/// auto-parse change, both of which sit *outside* every historical head's
/// ancestry. Ref-scoped replay (`kin review shadow`, `locate --ref git:<oid>`)
/// then reports blast radius 0 for entities whose only consumers are in those
/// untouched files.
///
/// # What
///
/// This walks the actual Git parents of every imported commit. For each distinct
/// parent omitted by the history window it inserts one root change carrying
/// every file in that parent's tree as an Addition (`parents = [genesis_id]`),
/// then rebuilds the child's parent list in original Git order with the
/// corresponding base-link id. Sharing one anchor for repeated edges to the
/// same omitted commit preserves diamond provenance. It also avoids collapsing
/// two omitted merge parents into one genesis edge, which loses the independent
/// parent trees needed to replay a merge exactly.
///
/// `changes` must be oldest-first, as returned by `import_git_history_*`.
///
/// Returns the first inserted base-link change id in deterministic Git-OID
/// order, or `None` when no anchoring is needed. A linear window has exactly
/// one anchor, preserving the original API behavior; a truncated merge may
/// prepend several anchors.
///
/// # Determinism
///
/// Base ids are hashes of omitted parent OIDs. Anchors are emitted in OID order,
/// artifact deltas in path order, and author/timestamp come from Git commit
/// content, never wall-clock. Parent order continues to match Git. The output
/// is therefore byte-identical across runs for identical history + window.
pub fn anchor_imported_history_at_base_link(
    repo_path: &Path,
    changes: &mut Vec<ImportedChange>,
    genesis_id: SemanticChangeId,
    blob_store: Option<&BlobStore>,
) -> Result<Option<SemanticChangeId>> {
    if changes.is_empty() {
        return Ok(None);
    }

    let repo = open_repo(repo_path).map_err(|e| GitError::Git(e.to_string()))?;
    let shallow_boundaries = shallow_boundary_ids(&repo)?;
    let imported_ids: HashSet<SemanticChangeId> =
        changes.iter().map(|entry| entry.change.id).collect();
    let mut git_parent_oids = Vec::with_capacity(changes.len());
    let mut omitted_parents = BTreeSet::new();

    // `close_truncated_history_dag` intentionally makes the public raw import
    // self-contained by collapsing missing parents to genesis. Recover the
    // authoritative edge identities from each Git commit before anchoring so
    // no merge-parent provenance is lost at that compatibility boundary.
    for imported in changes.iter() {
        let oid = gix::ObjectId::from_hex(imported.git_oid.as_bytes())
            .map_err(|e| GitError::Git(format!("invalid git oid '{}': {}", imported.git_oid, e)))?;
        let commit = repo
            .find_commit(oid)
            .map_err(|e| GitError::CommitNotFound(format!("{oid}: {e}")))?;
        let mut parents = Vec::new();
        if !shallow_boundaries.contains(&oid) {
            for parent in commit.parent_ids() {
                if parents.len() == MAX_BASE_LINK_ANCHORS {
                    return Err(GitError::Other(format!(
                        "Git commit {oid} has more than {MAX_BASE_LINK_ANCHORS} direct parents; refusing an unbounded truncated-history boundary"
                    )));
                }
                let parent = parent.detach();
                if !imported_ids.contains(&change_id_from_git_oid(&parent))
                    && omitted_parents.insert(parent)
                {
                    // Enforce as the set grows so an adversarial octopus commit
                    // cannot be fully retained before the boundary is rejected.
                    enforce_base_link_budget(omitted_parents.len(), 0, 0)?;
                }
                parents.push(parent);
            }
        }
        git_parent_oids.push(parents);
    }

    if omitted_parents.is_empty() {
        return Ok(None);
    }
    let anchor_ids: BTreeMap<gix::ObjectId, SemanticChangeId> = omitted_parents
        .iter()
        .map(|oid| (*oid, base_link_change_id_from_git_oid(oid)))
        .collect();

    // Compute every replacement parent vector without mutating caller-owned
    // history. Anchor construction below is fallible (missing/corrupt Git
    // objects and blob persistence can fail), so publication must be atomic:
    // either every anchor and edge is ready, or `changes` stays byte-identical.
    let replacement_parents: Vec<Vec<SemanticChangeId>> = git_parent_oids
        .iter()
        .map(|parents| {
            if parents.is_empty() {
                vec![genesis_id]
            } else {
                parents
                    .iter()
                    .map(|parent| {
                        let imported_id = change_id_from_git_oid(parent);
                        if imported_ids.contains(&imported_id) {
                            imported_id
                        } else {
                            anchor_ids[parent]
                        }
                    })
                    .collect()
            }
        })
        .collect();

    let mut anchors = Vec::with_capacity(anchor_ids.len());
    let mut aggregate_entries = 0_usize;
    let mut aggregate_expanded_bytes = 0_u64;
    let mut blob_cache = HashMap::<gix::ObjectId, (Hash256, u64)>::new();
    for (parent_oid, base_id) in &anchor_ids {
        let parent_commit = repo
            .find_commit(*parent_oid)
            .map_err(|e| GitError::CommitNotFound(format!("{parent_oid}: {e}")))?;
        let parent_tree = parent_commit
            .tree()
            .map_err(|e| GitError::Git(e.to_string()))?;

        // Full parent universe as Added artifact deltas, in stable path order.
        // Materialize every blob so exact checkout/archive consumers have the
        // bytes corresponding to the graph-owned content identities.
        let remaining_entries = MAX_BASE_LINK_TREE_ENTRIES
            .checked_sub(aggregate_entries)
            .ok_or_else(|| GitError::Other("base-link entry count exceeds limit".to_string()))?;
        let entries = bounded_full_tree_blob_entries(&repo, &parent_tree, remaining_entries)?;
        aggregate_entries = aggregate_entries
            .checked_add(entries.len())
            .ok_or_else(|| GitError::Other("base-link entry count overflow".to_string()))?;
        enforce_base_link_budget(
            anchor_ids.len(),
            aggregate_entries,
            aggregate_expanded_bytes,
        )?;
        let mut artifact_deltas = Vec::with_capacity(entries.len());
        for (path, blob_id, entry_kind) in entries {
            let (new_hash, byte_len) = if let Some(cached) = blob_cache.get(&blob_id) {
                *cached
            } else {
                let header = repo
                    .find_header(blob_id)
                    .map_err(|error| GitError::Git(error.to_string()))?;
                if header.kind() != gix::objs::Kind::Blob {
                    return Err(GitError::Git(format!(
                        "source entry {path:?} points to non-blob Git object {blob_id} ({:?})",
                        header.kind()
                    )));
                }
                let byte_len = header.size();
                let prospective_bytes =
                    aggregate_expanded_bytes
                        .checked_add(byte_len)
                        .ok_or_else(|| {
                            GitError::Other("base-link source byte count overflow".into())
                        })?;
                enforce_base_link_budget(anchor_ids.len(), aggregate_entries, prospective_bytes)?;

                let mut blob = repo
                    .find_blob(blob_id)
                    .map_err(|error| GitError::Git(error.to_string()))?;
                let content = blob.take_data();
                let loaded_len = u64::try_from(content.len()).unwrap_or(u64::MAX);
                if loaded_len != byte_len {
                    return Err(GitError::Git(format!(
                        "Git blob {blob_id} changed size while loading: header={byte_len}, loaded={loaded_len}"
                    )));
                }
                let hash = Hash256::from_bytes(kin_blobs::digest(&content).0);
                if let Some(store) = blob_store {
                    store.write(&content)?;
                }
                blob_cache.insert(blob_id, (hash, byte_len));
                (hash, byte_len)
            };
            aggregate_expanded_bytes = aggregate_expanded_bytes
                .checked_add(byte_len)
                .ok_or_else(|| GitError::Other("base-link source byte count overflow".into()))?;
            enforce_base_link_budget(
                anchor_ids.len(),
                aggregate_entries,
                aggregate_expanded_bytes,
            )?;
            artifact_deltas.push(ArtifactDelta {
                file_id: FilePathId::new(path),
                kind: added_artifact_kind(entry_kind),
                old_hash: None,
                new_hash: Some(new_hash),
            });
        }

        let author_sig = parent_commit
            .author()
            .map_err(|e| GitError::Git(e.to_string()))?;
        let author = AuthorId::new(format!("{} <{}>", author_sig.name, author_sig.email));
        let git_time = author_sig
            .time()
            .map_err(|e| GitError::Git(e.to_string()))?;
        let timestamp = timestamp_from_git_seconds(git_time.seconds, parent_oid)?;

        anchors.push(ImportedChange {
            change: SemanticChange {
                id: *base_id,
                parents: vec![genesis_id],
                timestamp,
                author,
                // Preserve the original linear-anchor payload for existing
                // deterministic IDs while extending it to every boundary edge.
                message: "kin import: base-link (window base universe)".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas,
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: Some(BranchName::new("main")),
            },
            git_oid: parent_oid.to_string(),
        });
    }

    let first_anchor = anchors.first().map(|anchor| anchor.change.id);
    for (imported, parents) in changes.iter_mut().zip(replacement_parents) {
        imported.change.parents = parents;
    }
    // All roots precede every imported child. OID sorting above makes the
    // multi-anchor prefix deterministic without disturbing Git parent order.
    changes.splice(0..0, anchors);
    Ok(first_anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    #[test]
    fn test_open_repo_resolves_git_suffix_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("master_svelte.git");
        std::fs::create_dir(&repo_dir).unwrap();
        if !init_git_repo(&repo_dir) {
            return;
        }
        let repo = open_repo(&repo_dir)
            .expect("open_repo should succeed even on .git-suffixed directories");
        assert!(!repo.is_bare());
    }

    fn init_git_repo(dir: &std::path::Path) -> bool {
        let git_init = Command::new("git").args(["init"]).current_dir(dir).output();
        match git_init {
            Ok(output) if output.status.success() => {
                let _ = Command::new("git")
                    .args(["config", "user.email", "test@test.com"])
                    .current_dir(dir)
                    .output();
                let _ = Command::new("git")
                    .args(["config", "user.name", "Test"])
                    .current_dir(dir)
                    .output();
                let _ = Command::new("git")
                    .args(["config", "gc.auto", "0"])
                    .current_dir(dir)
                    .output();
                let _ = Command::new("git")
                    .args(["config", "core.hooksPath", ".git/no-hooks"])
                    .current_dir(dir)
                    .output();
                // Commit signing is a common global default and it hands the
                // terminal to a pinentry prompt. Nothing answers that prompt
                // during a test run, so an inherited value makes the commits
                // below wait forever instead of failing.
                let _ = Command::new("git")
                    .args(["config", "commit.gpgsign", "false"])
                    .current_dir(dir)
                    .output();
                let _ = Command::new("git")
                    .args(["config", "tag.gpgsign", "false"])
                    .current_dir(dir)
                    .output();
                true
            }
            _ => false,
        }
    }

    #[test]
    fn change_id_from_oid_is_deterministic() {
        let oid = gix::ObjectId::from_hex(b"aabbccddee00112233445566778899aabbccddee").unwrap();
        let id1 = change_id_from_git_oid(&oid);
        let id2 = change_id_from_git_oid(&oid);
        assert_eq!(id1, id2);
    }

    #[test]
    fn truncated_history_boundary_budget_fails_closed_at_each_dimension() {
        assert!(enforce_base_link_budget(
            MAX_BASE_LINK_ANCHORS,
            MAX_BASE_LINK_TREE_ENTRIES,
            MAX_BASE_LINK_EXPANDED_BYTES,
        )
        .is_ok());
        for error in [
            enforce_base_link_budget(MAX_BASE_LINK_ANCHORS + 1, 0, 0).unwrap_err(),
            enforce_base_link_budget(1, MAX_BASE_LINK_TREE_ENTRIES + 1, 0).unwrap_err(),
            enforce_base_link_budget(1, 1, MAX_BASE_LINK_EXPANDED_BYTES + 1).unwrap_err(),
        ] {
            assert!(error.to_string().contains("limit"));
        }
    }

    #[test]
    fn bounded_tree_enumeration_stops_at_entry_budget() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping bounded tree test");
            return;
        }
        std::fs::write(dir.path().join("a.txt"), b"a\n").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"b\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "a.txt", "b.txt"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-m", "two files"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());

        let repo = open_repo(dir.path()).unwrap();
        let tree = repo.head_commit().unwrap().tree().unwrap();
        assert_eq!(
            bounded_full_tree_blob_entries(&repo, &tree, 2)
                .unwrap()
                .len(),
            2
        );
        let error = bounded_full_tree_blob_entries(&repo, &tree, 1).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("remaining source-entry budget of 1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn different_oids_produce_different_ids() {
        let oid1 = gix::ObjectId::from_hex(b"aabbccddee00112233445566778899aabbccddee").unwrap();
        let oid2 = gix::ObjectId::from_hex(b"00112233445566778899aabbccddeeff00112233").unwrap();
        let id1 = change_id_from_git_oid(&oid1);
        let id2 = change_id_from_git_oid(&oid2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn git_import_rejects_out_of_range_author_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping invalid timestamp test");
            return;
        }

        std::fs::write(dir.path().join("owned.txt"), "owned\n").unwrap();
        let add = Command::new("git")
            .args(["add", "owned.txt"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(add.status.success());
        let tree = Command::new("git")
            .args(["write-tree"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(tree.status.success());
        let tree_oid = String::from_utf8(tree.stdout).unwrap();
        let raw_commit = format!(
            "tree {}\nauthor Test <test@test.com> {} +0000\ncommitter Test <test@test.com> {} +0000\n\nout of range\n",
            tree_oid.trim(),
            i64::MAX,
            i64::MAX
        );
        let mut hash = Command::new("git")
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .current_dir(dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        hash.stdin
            .take()
            .unwrap()
            .write_all(raw_commit.as_bytes())
            .unwrap();
        let hash = hash.wait_with_output().unwrap();
        assert!(
            hash.status.success(),
            "git rejected raw commit fixture: {}",
            String::from_utf8_lossy(&hash.stderr)
        );
        let commit_oid = String::from_utf8(hash.stdout).unwrap();
        let update = Command::new("git")
            .args(["update-ref", "HEAD", commit_oid.trim()])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(update.status.success());

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x24; 32]));
        let first = import_git_history(
            dir.path(),
            genesis_id,
            &ImportOptions {
                shallow: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        let second = import_git_history(
            dir.path(),
            genesis_id,
            &ImportOptions {
                shallow: true,
                ..Default::default()
            },
        )
        .unwrap_err();

        assert!(first.to_string().contains("outside Kin's supported range"));
        assert_eq!(first.to_string(), second.to_string());
    }

    #[test]
    fn import_options_default() {
        let opts = ImportOptions::default();
        assert!(!opts.shallow);
        assert_eq!(opts.max_commits, 0);
        assert!(opts.branch.is_none());
    }

    #[test]
    fn import_with_blobs_materializes_artifact_content() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping blob materialization test");
            return;
        }

        let nested_dir = dir.path().join("src");
        std::fs::create_dir_all(&nested_dir).unwrap();
        let file_path = nested_dir.join("hello.txt");
        let content = b"hello from git import\n";
        std::fs::write(&file_path, content).unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output();
        let _ = Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(dir.path())
            .output();

        let blob_store = BlobStore::new(dir.path().join("kin-blobs")).unwrap();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        let imported = import_git_history_with_blobs(
            dir.path(),
            genesis_id,
            &ImportOptions::default(),
            Some(&blob_store),
        )
        .expect("git import should succeed");

        let imported_blob = imported
            .iter()
            .flat_map(|change| change.change.artifact_deltas.iter())
            .find_map(|delta| delta.new_hash)
            .expect("import should record a blob-backed artifact hash");

        let stored = blob_store
            .read(&kin_blobs::Hash256(imported_blob.0))
            .expect("import should materialize blob content");
        assert_eq!(stored, content);
    }

    #[cfg(unix)]
    #[test]
    fn import_preserves_regular_executable_symlink_and_mode_only_changes() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping source mode import test");
            return;
        }

        let regular_path = dir.path().join("plain.txt");
        let executable_path = dir.path().join("run.sh");
        std::fs::write(&regular_path, b"plain\n").unwrap();
        std::fs::write(&executable_path, b"#!/bin/sh\necho exact\n").unwrap();
        let mut executable_permissions = std::fs::metadata(&executable_path).unwrap().permissions();
        executable_permissions.set_mode(0o755);
        std::fs::set_permissions(&executable_path, executable_permissions).unwrap();
        symlink("plain.txt", dir.path().join("plain-link")).unwrap();
        let initial = Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(initial.success());
        let initial = Command::new("git")
            .args(["commit", "-m", "exact source modes"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(initial.success());

        let mut regular_permissions = std::fs::metadata(&regular_path).unwrap().permissions();
        regular_permissions.set_mode(0o755);
        std::fs::set_permissions(&regular_path, regular_permissions).unwrap();
        let mode_change = Command::new("git")
            .args(["add", "plain.txt"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(mode_change.success());
        let mode_change = Command::new("git")
            .args(["commit", "-m", "make plain executable"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(mode_change.success());

        let blob_store = BlobStore::new(dir.path().join("kin-blobs")).unwrap();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x12; 32]));
        let imported = import_git_history_with_blobs(
            dir.path(),
            genesis_id,
            &ImportOptions::default(),
            Some(&blob_store),
        )
        .expect("git import should preserve source modes");
        assert_eq!(imported.len(), 2);

        let initial_kinds: std::collections::BTreeMap<_, _> = imported[0]
            .change
            .artifact_deltas
            .iter()
            .map(|delta| (delta.file_id.0.as_str(), delta.kind))
            .collect();
        assert_eq!(
            initial_kinds.get("plain.txt"),
            Some(&ArtifactDeltaKind::AddedRegularFile)
        );
        assert_eq!(
            initial_kinds.get("run.sh"),
            Some(&ArtifactDeltaKind::AddedExecutableFile)
        );
        assert_eq!(
            initial_kinds.get("plain-link"),
            Some(&ArtifactDeltaKind::AddedSymlink)
        );
        let link_delta = imported[0]
            .change
            .artifact_deltas
            .iter()
            .find(|delta| delta.file_id.0 == "plain-link")
            .unwrap();
        let link_target = blob_store
            .read(&kin_blobs::Hash256(link_delta.new_hash.unwrap().0))
            .unwrap();
        assert_eq!(link_target, b"plain.txt");

        assert_eq!(imported[1].change.artifact_deltas.len(), 1);
        let mode_delta = &imported[1].change.artifact_deltas[0];
        assert_eq!(mode_delta.file_id.0, "plain.txt");
        assert_eq!(mode_delta.kind, ArtifactDeltaKind::ModifiedExecutableFile);
        assert_eq!(mode_delta.old_hash, mode_delta.new_hash);
    }

    #[test]
    fn exact_import_records_gitlinks_as_tracked_pointer_changes() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping gitlink import test");
            return;
        }

        std::fs::write(dir.path().join("seed.txt"), "seed\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "seed.txt"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-m", "seed"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
        let head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(head.status.success());
        let head = String::from_utf8(head.stdout).unwrap();
        let cache_info = format!("160000,{},vendor/sub", head.trim());
        assert!(Command::new("git")
            .args(["update-index", "--add", "--cacheinfo", &cache_info])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-m", "add gitlink"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());

        // A submodule in history must not block import (regression: it used to
        // be refused). The pointer is recorded as a tracked, mode-unknown
        // artifact delta carrying the pinned commit as content — not refused,
        // not silently omitted, and not mislabeled as a file.
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x13; 32]));
        let imported = import_git_history(dir.path(), genesis_id, &ImportOptions::default())
            .expect("a submodule pointer is recorded as a tracked change, not refused");

        let gitlink = imported
            .iter()
            .flat_map(|change| &change.change.artifact_deltas)
            .find(|delta| delta.file_id.0 == "vendor/sub")
            .expect("the gitlink pointer is recorded as an artifact delta");
        assert_eq!(gitlink.kind, ArtifactDeltaKind::Added);
        // Mode-unknown on purpose: a submodule is not an exact-source file kind,
        // so it resolves to a source-tree gap rather than a fabricated file.
        assert_eq!(gitlink.kind.source_entry_kind(), None);
        // The pinned commit is captured as the delta's content identity.
        assert!(gitlink.new_hash.is_some());
        assert!(gitlink.old_hash.is_none());
    }

    #[test]
    fn exact_import_path_decoder_rejects_non_utf8_bytes() {
        let error = utf8_git_path(b"invalid-\xff.rs")
            .expect_err("an exact import must not record a lossy path identity");
        assert!(error.to_string().contains("non-UTF-8 path"));
    }

    // Linux filesystems accept arbitrary non-NUL path bytes. macOS's filesystem
    // APIs reject this fixture at creation time, so the end-to-end repository
    // case belongs on Linux while the decoder unit test above runs everywhere.
    #[cfg(target_os = "linux")]
    #[test]
    fn exact_import_rejects_non_utf8_paths_instead_of_lossy_identity() {
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping non-UTF-8 path rejection test");
            return;
        }

        let name = std::ffi::OsString::from_vec(b"invalid-\xff.rs".to_vec());
        std::fs::write(dir.path().join(name), "fn invalid() {}\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "-A"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-m", "non utf8 path"])
            .current_dir(dir.path())
            .status()
            .unwrap()
            .success());

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x14; 32]));
        let error = import_git_history(dir.path(), genesis_id, &ImportOptions::default())
            .expect_err("an exact import must not record a lossy path identity");
        assert!(error.to_string().contains("non-UTF-8 path"));
    }

    #[test]
    fn import_tracks_only_changed_files_for_non_root_commits() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping delta tracking test");
            return;
        }

        std::fs::write(dir.path().join("alpha.txt"), "a1\n").unwrap();
        std::fs::write(dir.path().join("beta.txt"), "b1\n").unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output();
        let _ = Command::new("git")
            .args(["commit", "-m", "initial"])
            .env("GIT_AUTHOR_DATE", "1000000000 +0000")
            .env("GIT_COMMITTER_DATE", "1000000000 +0000")
            .current_dir(dir.path())
            .output();

        std::fs::write(dir.path().join("alpha.txt"), "a2\n").unwrap();
        let _ = Command::new("git")
            .args(["add", "alpha.txt"])
            .current_dir(dir.path())
            .output();
        let _ = Command::new("git")
            .args(["commit", "-m", "modify alpha"])
            .env("GIT_AUTHOR_DATE", "1000000100 +0000")
            .env("GIT_COMMITTER_DATE", "1000000100 +0000")
            .current_dir(dir.path())
            .output();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32]));
        let imported = import_git_history(dir.path(), genesis_id, &ImportOptions::default())
            .expect("git import should succeed");
        let latest = imported.last().expect("expected imported commits");
        let paths = latest
            .change
            .artifact_deltas
            .iter()
            .map(|delta| (delta.file_id.0.clone(), delta.kind))
            .collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![(
                "alpha.txt".to_string(),
                ArtifactDeltaKind::ModifiedRegularFile,
            )]
        );
    }

    #[test]
    fn anchor_base_link_carries_full_base_tree_and_reparents_window_base() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping base-link anchor test");
            return;
        }

        let commit = |msg: &str, epoch: i64| {
            let stamp = format!("{epoch} +0000");
            let _ = Command::new("git")
                .args(["add", "."])
                .current_dir(dir.path())
                .output();
            let _ = Command::new("git")
                .args(["commit", "-m", msg])
                .env("GIT_AUTHOR_DATE", &stamp)
                .env("GIT_COMMITTER_DATE", &stamp)
                .current_dir(dir.path())
                .output();
        };

        // c1 (base, will fall OUTSIDE a 3-commit window): both files exist.
        std::fs::write(dir.path().join("alpha.txt"), "a1\n").unwrap();
        std::fs::write(dir.path().join("beta.txt"), "b1\n").unwrap();
        commit("c1 base", 1_000_000_000);
        // c2..c4: touch alpha.txt only — beta.txt is untouched across the window.
        std::fs::write(dir.path().join("alpha.txt"), "a2\n").unwrap();
        commit("c2", 1_000_000_100);
        std::fs::write(dir.path().join("alpha.txt"), "a3\n").unwrap();
        commit("c3", 1_000_000_200);
        std::fs::write(dir.path().join("alpha.txt"), "a4\n").unwrap();
        commit("c4", 1_000_000_300);

        let blob_store = BlobStore::new(dir.path().join("kin-blobs")).unwrap();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x33; 32]));
        let mut imported = import_git_history_with_blobs(
            dir.path(),
            genesis_id,
            &ImportOptions {
                max_commits: 3,
                ..Default::default()
            },
            Some(&blob_store),
        )
        .expect("git import should succeed");

        // Truncated to the newest 3 commits (c2, c3, c4); c2's real parent (c1)
        // is out of window, so beta.txt appears in NO windowed artifact delta.
        assert_eq!(imported.len(), 3, "window should hold exactly 3 commits");
        assert!(
            imported
                .iter()
                .flat_map(|ic| ic.change.artifact_deltas.iter())
                .all(|d| d.file_id.0 != "beta.txt"),
            "pre-anchor: the untouched consumer file must not appear in any windowed commit"
        );
        let window_base_id = imported[0].change.id;
        assert_eq!(
            imported[0].change.parents,
            vec![genesis_id],
            "pre-anchor: window base's out-of-window parent is re-pointed to genesis"
        );

        let base_id = anchor_imported_history_at_base_link(
            dir.path(),
            &mut imported,
            genesis_id,
            Some(&blob_store),
        )
        .expect("anchoring should succeed")
        .expect("a truncated window should yield a base-link change");

        // The base-link is prepended, rooted at genesis, and carries the FULL
        // base tree (both files) — including the untouched consumer beta.txt.
        assert_eq!(imported.len(), 4, "base-link prepended to the window");
        assert_eq!(imported[0].change.id, base_id);
        assert_eq!(imported[0].change.parents, vec![genesis_id]);
        let base_paths: Vec<(String, ArtifactDeltaKind)> = imported[0]
            .change
            .artifact_deltas
            .iter()
            .map(|d| (d.file_id.0.clone(), d.kind))
            .collect();
        assert_eq!(
            base_paths,
            vec![
                ("alpha.txt".to_string(), ArtifactDeltaKind::AddedRegularFile,),
                ("beta.txt".to_string(), ArtifactDeltaKind::AddedRegularFile,),
            ],
            "base-link must carry the full base universe as sorted Additions"
        );

        // The window base is re-parented off genesis onto the base-link, so
        // every head's first-parent ancestry now flows through the base universe.
        let reparented = imported
            .iter()
            .find(|ic| ic.change.id == window_base_id)
            .expect("window base still present");
        assert_eq!(
            reparented.change.parents.first().copied(),
            Some(base_id),
            "window base's first parent must be re-pointed to the base-link"
        );
    }

    #[test]
    fn anchor_base_link_is_noop_for_full_import_true_root() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping base-link no-op test");
            return;
        }

        std::fs::write(dir.path().join("alpha.txt"), "a1\n").unwrap();
        std::fs::write(dir.path().join("beta.txt"), "b1\n").unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output();
        let _ = Command::new("git")
            .args(["commit", "-m", "root"])
            .env("GIT_AUTHOR_DATE", "1000000000 +0000")
            .env("GIT_COMMITTER_DATE", "1000000000 +0000")
            .current_dir(dir.path())
            .output();

        let blob_store = BlobStore::new(dir.path().join("kin-blobs")).unwrap();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x44; 32]));
        let mut imported = import_git_history_with_blobs(
            dir.path(),
            genesis_id,
            &ImportOptions::default(),
            Some(&blob_store),
        )
        .expect("git import should succeed");
        let before = imported.len();

        let result = anchor_imported_history_at_base_link(
            dir.path(),
            &mut imported,
            genesis_id,
            Some(&blob_store),
        )
        .expect("anchoring should succeed");

        assert!(
            result.is_none(),
            "a full import whose oldest commit is a true Git root needs no base-link"
        );
        assert_eq!(
            imported.len(),
            before,
            "no synthetic change should be added"
        );
    }

    #[test]
    fn anchor_base_link_failure_leaves_imported_history_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping base-link atomic failure test");
            return;
        }

        for (index, contents) in ["one\n", "two\n"].into_iter().enumerate() {
            std::fs::write(dir.path().join("alpha.txt"), contents).unwrap();
            let _ = Command::new("git")
                .args(["add", "alpha.txt"])
                .current_dir(dir.path())
                .output();
            let stamp = format!("{} +0000", 1_000_000_000 + index as i64);
            let output = Command::new("git")
                .args(["commit", "-m", &format!("c{}", index + 1)])
                .env("GIT_AUTHOR_DATE", &stamp)
                .env("GIT_COMMITTER_DATE", &stamp)
                .current_dir(dir.path())
                .output()
                .unwrap();
            assert!(output.status.success());
        }

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x45; 32]));
        let mut imported = import_git_history(
            dir.path(),
            genesis_id,
            &ImportOptions {
                max_commits: 1,
                ..Default::default()
            },
        )
        .expect("truncated import should succeed before object corruption");
        let before: Vec<_> = imported
            .iter()
            .map(|entry| (entry.git_oid.clone(), format!("{:?}", entry.change)))
            .collect();

        let parent_oid = Command::new("git")
            .args(["rev-parse", "HEAD^"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(parent_oid.status.success());
        let parent_oid = String::from_utf8(parent_oid.stdout).unwrap();
        let parent_oid = parent_oid.trim();
        let parent_object = dir
            .path()
            .join(".git/objects")
            .join(&parent_oid[..2])
            .join(&parent_oid[2..]);
        std::fs::remove_file(&parent_object).expect("fixture parent commit must be loose");

        let error =
            anchor_imported_history_at_base_link(dir.path(), &mut imported, genesis_id, None)
                .expect_err("missing boundary parent object must fail anchoring");
        assert!(
            error.to_string().contains(parent_oid),
            "error must identify the missing parent: {error}"
        );

        let after: Vec<_> = imported
            .iter()
            .map(|entry| (entry.git_oid.clone(), format!("{:?}", entry.change)))
            .collect();
        assert_eq!(after, before, "failed anchoring must not reparent history");
    }

    #[test]
    fn import_to_specific_commit_limits_history_to_target_ancestry() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping targeted import test");
            return;
        }

        std::fs::write(dir.path().join("alpha.txt"), "a1\n").unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output();
        let _ = Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(dir.path())
            .output();
        let first = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        let first_oid = String::from_utf8_lossy(&first.stdout).trim().to_string();

        std::fs::write(dir.path().join("alpha.txt"), "a2\n").unwrap();
        let _ = Command::new("git")
            .args(["add", "alpha.txt"])
            .current_dir(dir.path())
            .output();
        let _ = Command::new("git")
            .args(["commit", "-m", "modify alpha"])
            .current_dir(dir.path())
            .output();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x33; 32]));
        let imported =
            import_git_history_to_commit_with_blobs(dir.path(), &first_oid, genesis_id, None)
                .expect("targeted git import should succeed");

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].git_oid, first_oid);
    }

    /// Build a git repo with `num_commits` commits, each touching a couple of
    /// files, using a deterministic xorshift selection (no wall-clock / RNG) so
    /// the history is reproducible. Returns the repo's tempdir.
    fn build_test_repo(num_commits: usize, num_files: usize) -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            return None;
        }
        std::fs::create_dir_all(dir.path().join("src")).unwrap();

        let mut state: u64 = 0xC0FFEE | 1;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };

        for c in 0..num_commits {
            // Touch two adjacent files, content keyed on the commit index so each
            // commit produces a distinct tree (and distinct blobs).
            let base = (next() as usize) % num_files;
            for k in 0..2 {
                let f = (base + k) % num_files;
                let path = dir.path().join("src").join(format!("f{f}.rs"));
                std::fs::write(&path, format!("// f{f} rev {c}\nfn f{f}_{c}() {{}}\n")).unwrap();
            }
            let _ = Command::new("git")
                .args(["add", "."])
                .current_dir(dir.path())
                .output();
            let _ = Command::new("git")
                .args(["commit", "-m", &format!("commit {c}")])
                // Every commit shares one timestamp on purpose: equal-time ties
                // are the case the deterministic selection order exists for, so
                // the identity tests exercise it on every run instead of only on
                // machines fast enough to commit twice in one second.
                .env("GIT_AUTHOR_DATE", "1000000000 +0000")
                .env("GIT_COMMITTER_DATE", "1000000000 +0000")
                .current_dir(dir.path())
                .output();
        }
        Some(dir)
    }

    /// Build a git repo whose commits all share ONE pinned committer/author
    /// timestamp, so a `ByCommitTime` walk cannot order them by time — the exact
    /// condition under which a raw `take(max_commits)` truncation (or an
    /// order-sensitive downstream consumer) becomes process-dependent. Each commit
    /// still touches a distinct file, so every commit has a distinct tree and oid.
    fn build_equal_timestamp_repo(num_commits: usize) -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            return None;
        }
        // Disable any globally-configured hooks for this throwaway repo so a
        // commit-date-rewriting hook cannot override the pinned dates below (a
        // clean CI checkout has no such hook; this only neutralizes a local one).
        let _ = Command::new("git")
            .args(["config", "core.hooksPath", "/dev/null"])
            .current_dir(dir.path())
            .output();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();

        // One fixed instant for every commit (a real git epoch string). Author and
        // committer dates are pinned so the committer time — what `ByCommitTime`
        // sorts on — ties across all commits.
        let fixed_date = "1112911993 +0000";
        for c in 0..num_commits {
            let path = dir.path().join("src").join(format!("f{c}.rs"));
            std::fs::write(&path, format!("fn f{c}() {{}}\n")).unwrap();
            let _ = Command::new("git")
                .args(["add", "."])
                .current_dir(dir.path())
                .output();
            let _ = Command::new("git")
                .args(["commit", "-m", &format!("commit {c}")])
                .env("GIT_AUTHOR_DATE", fixed_date)
                .env("GIT_COMMITTER_DATE", fixed_date)
                .current_dir(dir.path())
                .output();
        }
        Some(dir)
    }

    fn run_dated_git(dir: &Path, args: &[&str], fixed_date: &str) {
        let output = Command::new("git")
            .args(args)
            .env("GIT_AUTHOR_DATE", fixed_date)
            .env("GIT_COMMITTER_DATE", fixed_date)
            .current_dir(dir)
            .output()
            .expect("run git command");
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn build_equal_timestamp_merge_repo() -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            return None;
        }
        let _ = Command::new("git")
            .args(["config", "core.hooksPath", "/dev/null"])
            .current_dir(dir.path())
            .output();
        let fixed_date = "1112911993 +0000";

        run_dated_git(
            dir.path(),
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            fixed_date,
        );
        std::fs::write(dir.path().join("root.txt"), "root\n").unwrap();
        run_dated_git(dir.path(), &["add", "root.txt"], fixed_date);
        run_dated_git(dir.path(), &["commit", "-m", "root"], fixed_date);

        run_dated_git(dir.path(), &["switch", "-c", "feature"], fixed_date);
        std::fs::write(dir.path().join("feature.txt"), "feature\n").unwrap();
        run_dated_git(dir.path(), &["add", "feature.txt"], fixed_date);
        run_dated_git(dir.path(), &["commit", "-m", "feature"], fixed_date);

        run_dated_git(dir.path(), &["switch", "main"], fixed_date);
        std::fs::write(dir.path().join("main.txt"), "main\n").unwrap();
        run_dated_git(dir.path(), &["add", "main.txt"], fixed_date);
        run_dated_git(dir.path(), &["commit", "-m", "main"], fixed_date);
        run_dated_git(
            dir.path(),
            &["merge", "--no-ff", "feature", "-m", "merge"],
            fixed_date,
        );

        Some(dir)
    }

    fn build_truncated_merge_correction_repo() -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            return None;
        }
        let _ = Command::new("git")
            .args(["config", "core.hooksPath", "/dev/null"])
            .current_dir(dir.path())
            .output();
        let fixed_date = "1112911993 +0000";

        run_dated_git(
            dir.path(),
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            fixed_date,
        );
        std::fs::write(
            dir.path().join("gone.txt"),
            "retained only by second parent\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("conflict.txt"), "base\n").unwrap();
        std::fs::write(dir.path().join("mode.sh"), "#!/bin/sh\necho stable\n").unwrap();
        run_dated_git(dir.path(), &["add", "."], fixed_date);
        run_dated_git(dir.path(), &["commit", "-m", "base"], fixed_date);

        run_dated_git(dir.path(), &["switch", "-c", "feature"], fixed_date);
        std::fs::write(dir.path().join("conflict.txt"), "feature content\n").unwrap();
        std::fs::write(dir.path().join("feature-only.txt"), "feature\n").unwrap();
        run_dated_git(dir.path(), &["add", "."], fixed_date);
        run_dated_git(dir.path(), &["commit", "-m", "feature"], fixed_date);

        run_dated_git(dir.path(), &["switch", "main"], fixed_date);
        std::fs::remove_file(dir.path().join("gone.txt")).unwrap();
        std::fs::write(dir.path().join("conflict.txt"), "main content\n").unwrap();
        run_dated_git(dir.path(), &["add", "-A"], fixed_date);
        run_dated_git(
            dir.path(),
            &["update-index", "--chmod=+x", "mode.sh"],
            fixed_date,
        );
        run_dated_git(dir.path(), &["commit", "-m", "main"], fixed_date);
        run_dated_git(
            dir.path(),
            &["merge", "--no-ff", "-X", "ours", "feature", "-m", "merge"],
            fixed_date,
        );

        Some(dir)
    }

    fn assert_import_order_is_parent_first(changes: &[ImportedChange]) {
        let positions: HashMap<SemanticChangeId, usize> = changes
            .iter()
            .enumerate()
            .map(|(index, imported)| (imported.change.id, index))
            .collect();
        for (child_index, imported) in changes.iter().enumerate() {
            for parent in &imported.change.parents {
                if let Some(parent_index) = positions.get(parent) {
                    assert!(
                        *parent_index < child_index,
                        "selected parent {parent} at {parent_index} must precede child {} at {child_index}",
                        imported.change.id
                    );
                }
            }
        }
    }

    /// Determinism regression: two preps of byte-identical history must select
    /// the same HEAD-rooted window and emit it in stable parent-first order.
    /// When every commit shares a timestamp, neither the raw walk order nor a
    /// global oid cutoff may decide the branch tip: HEAD and its contiguous
    /// ancestry are authoritative, with oid used only between frontier parents.
    #[test]
    fn import_full_truncation_is_deterministic_under_equal_timestamps() {
        let Some(dir) = build_equal_timestamp_repo(8) else {
            eprintln!("git not available, skipping equal-timestamp determinism test");
            return;
        };
        let repo = open_repo(dir.path()).expect("open repo");
        let head_id = repo
            .head_ref()
            .expect("head_ref")
            .expect("non-empty repo")
            .id()
            .detach();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));

        // The full import enumerates every commit; its ids are the ground truth.
        let full = import_full(&repo, head_id, genesis_id, 0, None).expect("full import");
        assert_eq!(full.len(), 8, "all commits import when max_commits == 0");
        assert_import_order_is_parent_first(&full);

        // This fixture must exercise the old defect: reversing oid order is not
        // a valid ancestry order for this equal-timestamp chain.
        let full_oids: Vec<String> = full.iter().map(|c| c.git_oid.clone()).collect();
        let mut naive_oid_order = full_oids.clone();
        naive_oid_order.sort();
        naive_oid_order.reverse();
        assert_ne!(
            full_oids, naive_oid_order,
            "fixture must distinguish parent-first order from reversed oid order"
        );

        // A linear history's bounded window is exactly its newest four commits,
        // ending at HEAD even though every timestamp is tied.
        let expected_order = full_oids[full_oids.len() - 4..].to_vec();

        // Two independent truncated imports must both equal the expected
        // parent-first order, proving selection and emission are deterministic
        // without conflating their authorities.
        let head_oid = head_id.to_string();
        for _ in 0..2 {
            let limited = import_full(&repo, head_id, genesis_id, 4, None).expect("limited import");
            let got_oids: Vec<String> = limited.iter().map(|c| c.git_oid.clone()).collect();
            assert_eq!(
                got_oids, expected_order,
                "equal-timestamp truncation must keep the contiguous HEAD-rooted window"
            );
            assert_import_order_is_parent_first(&limited);
            assert_eq!(
                limited.last().map(|change| change.git_oid.as_str()),
                Some(head_oid.as_str()),
                "the imported branch head must remain the requested Git HEAD"
            );
            for imported in &limited {
                assert_eq!(
                    imported.change.id,
                    semantic_change_id_from_git_oid_hex(&imported.git_oid).expect("valid oid"),
                    "imported change id must remain bound to its Git oid"
                );
            }
        }
    }

    #[test]
    fn import_full_orders_equal_timestamp_merge_dag_parent_first() {
        let Some(dir) = build_equal_timestamp_merge_repo() else {
            eprintln!("git not available, skipping equal-timestamp merge-DAG test");
            return;
        };
        let repo = open_repo(dir.path()).expect("open repo");
        let head_id = repo
            .head_ref()
            .expect("head_ref")
            .expect("non-empty repo")
            .id()
            .detach();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x57; 32]));

        let first = import_full(&repo, head_id, genesis_id, 0, None).expect("first full import");
        let second = import_full(&repo, head_id, genesis_id, 0, None).expect("second full import");
        assert_eq!(
            first.len(),
            4,
            "root, two branch tips, and merge must import"
        );
        assert_import_order_is_parent_first(&first);
        assert_eq!(
            first.iter().map(|c| &c.git_oid).collect::<Vec<_>>(),
            second.iter().map(|c| &c.git_oid).collect::<Vec<_>>(),
            "equal-timestamp merge-DAG order must be repeatable"
        );

        let positions: HashMap<String, usize> = first
            .iter()
            .enumerate()
            .map(|(index, imported)| (imported.git_oid.clone(), index))
            .collect();
        let merge = repo
            .find_object(head_id)
            .expect("find merge commit")
            .into_commit();
        let merge_index = positions[&head_id.to_string()];
        let merge_parents: Vec<String> = merge.parent_ids().map(|id| id.to_string()).collect();
        assert_eq!(merge_parents.len(), 2, "fixture must contain a real merge");
        for parent in merge_parents {
            assert!(
                positions[&parent] < merge_index,
                "both merge parents must precede the merge commit"
            );
        }

        let head_oid = head_id.to_string();
        let limited =
            import_full(&repo, head_id, genesis_id, 2, None).expect("bounded merge import");
        assert_eq!(limited.len(), 2, "bounded window keeps HEAD and one parent");
        assert_import_order_is_parent_first(&limited);
        assert_eq!(
            limited.last().map(|change| change.git_oid.as_str()),
            Some(head_oid.as_str()),
            "bounded merge history must still end at the requested HEAD"
        );
        let selected_parent = limited[0].change.id;
        let bounded_head = &limited[1].change;
        assert!(
            bounded_head.parents.contains(&selected_parent),
            "the selected frontier parent must remain connected to HEAD"
        );
        assert!(
            bounded_head.parents.contains(&genesis_id),
            "the omitted merge parent must close at the history boundary"
        );
    }

    #[test]
    fn truncated_merge_anchors_every_boundary_parent_and_replays_exact_archive() {
        use kin_model::{ChangeStore, SourceTreeResolution};

        let Some(dir) = build_equal_timestamp_merge_repo() else {
            eprintln!("git not available, skipping merge-boundary anchor test");
            return;
        };
        let repo = open_repo(dir.path()).expect("open repo");
        let head_id = repo
            .head_ref()
            .expect("head_ref")
            .expect("non-empty repo")
            .id()
            .detach();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x68; 32]));
        let blob_store = BlobStore::new(dir.path().join("boundary-blobs")).unwrap();

        // Keep only the merge. Both sides of the root -> {main, feature} ->
        // merge diamond cross the truncation boundary independently.
        let mut imported = import_full(&repo, head_id, genesis_id, 1, Some(&blob_store))
            .expect("bounded merge import");
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].change.parents, vec![genesis_id]);

        anchor_imported_history_at_base_link(
            dir.path(),
            &mut imported,
            genesis_id,
            Some(&blob_store),
        )
        .expect("anchor every omitted merge parent")
        .expect("truncated merge must create boundary anchors");

        assert_eq!(
            imported.len(),
            3,
            "two full-tree roots must precede the one imported merge"
        );
        let merge = imported.last().expect("merge remains the imported head");
        assert_eq!(merge.change.parents.len(), 2);
        assert!(merge
            .change
            .parents
            .iter()
            .all(|parent| *parent != genesis_id));

        // Parent order and identity remain the original Git provenance, rather
        // than two boundary edges collapsing into one anonymous genesis edge.
        let anchor_oid_by_id: HashMap<_, _> = imported[..2]
            .iter()
            .map(|anchor| (anchor.change.id, anchor.git_oid.clone()))
            .collect();
        let git_merge = repo.find_commit(head_id).expect("find merge commit");
        let expected_parent_oids: Vec<_> = git_merge
            .parent_ids()
            .map(|parent| parent.to_string())
            .collect();
        let replay_parent_oids: Vec<_> = merge
            .change
            .parents
            .iter()
            .map(|parent| anchor_oid_by_id[parent].clone())
            .collect();
        assert_eq!(replay_parent_oids, expected_parent_oids);

        // Each synthetic boundary node is independently exact and carries its
        // omitted parent's complete tree, not merely files touched in-window.
        for anchor in &imported[..2] {
            assert_eq!(anchor.change.parents, vec![genesis_id]);
            let parent_oid = gix::ObjectId::from_hex(anchor.git_oid.as_bytes()).unwrap();
            let parent_tree = repo.find_commit(parent_oid).unwrap().tree().unwrap();
            let expected_paths: Vec<_> = full_tree_blob_entries(&repo, &parent_tree)
                .unwrap()
                .into_iter()
                .map(|(path, _, class)| (path, added_delta_kind(class)))
                .collect();
            let anchor_paths: Vec<_> = anchor
                .change
                .artifact_deltas
                .iter()
                .map(|delta| (delta.file_id.0.clone(), delta.kind))
                .collect();
            assert_eq!(anchor_paths, expected_paths);
        }

        let graph = kin_db::InMemoryGraph::new();
        let genesis = bare_change(genesis_id, vec![]).change;
        graph.create_change(&genesis).unwrap();
        for change in &imported {
            graph.create_change(&change.change).unwrap();
        }
        let SourceTreeResolution::Exact { entries } =
            graph.resolve_source_tree_at(&merge.change.id).unwrap()
        else {
            panic!("anchored truncated merge must resolve to an exact source tree")
        };

        // Compare an archive-shaped manifest (path, mode, bytes) against the
        // authoritative Git merge tree. This proves both graph identities and
        // persisted object bytes are sufficient to reproduce the exact archive.
        let head_tree = git_merge.tree().unwrap();
        let expected_entries = full_tree_blob_entries(&repo, &head_tree).unwrap();
        let mut expected_archive = Vec::new();
        for (path, blob_oid, class) in expected_entries {
            let GitEntryClass::Source(kind) = class else {
                unreachable!("merge fixture contains no submodules");
            };
            let bytes = repo.find_blob(blob_oid).unwrap().take_data();
            expected_archive.push((path, kind, bytes));
        }
        let mut replay_archive = Vec::new();
        let mut resolved: Vec<_> = entries.into_iter().collect();
        resolved.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        for (path, entry) in resolved {
            let bytes = blob_store
                .read(&kin_blobs::Hash256(*entry.hash.as_bytes()))
                .unwrap();
            replay_archive.push((path.0, entry.kind, bytes));
        }
        assert_eq!(replay_archive, expected_archive);
    }

    #[test]
    fn truncated_merge_correction_preserves_deletion_content_and_mode_choices() {
        use kin_model::{ChangeStore, SourceTreeResolution};

        let Some(dir) = build_truncated_merge_correction_repo() else {
            eprintln!("git not available, skipping merge-correction test");
            return;
        };
        let repo = open_repo(dir.path()).expect("open repo");
        let head_id = repo
            .head_ref()
            .expect("head_ref")
            .expect("non-empty repo")
            .id()
            .detach();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x69; 32]));
        let blob_store = BlobStore::new(dir.path().join("correction-blobs")).unwrap();

        let mut imported = import_full(&repo, head_id, genesis_id, 1, Some(&blob_store))
            .expect("bounded merge import");
        anchor_imported_history_at_base_link(
            dir.path(),
            &mut imported,
            genesis_id,
            Some(&blob_store),
        )
        .expect("anchor omitted merge parents")
        .expect("truncated merge must create anchors");

        let merge = imported.last().expect("merge remains imported head");
        let by_path: HashMap<_, _> = merge
            .change
            .artifact_deltas
            .iter()
            .map(|delta| (delta.file_id.0.as_str(), delta.kind))
            .collect();
        assert_eq!(by_path["gone.txt"], ArtifactDeltaKind::Removed);
        assert_eq!(
            by_path["conflict.txt"],
            ArtifactDeltaKind::ModifiedRegularFile
        );
        assert_eq!(
            by_path["mode.sh"],
            ArtifactDeltaKind::ModifiedExecutableFile
        );

        let graph = kin_db::InMemoryGraph::new();
        graph
            .create_change(&bare_change(genesis_id, vec![]).change)
            .unwrap();
        for change in &imported {
            graph.create_change(&change.change).unwrap();
        }
        let SourceTreeResolution::Exact { entries } =
            graph.resolve_source_tree_at(&merge.change.id).unwrap()
        else {
            panic!("truncated merge correction must resolve exactly")
        };

        let git_merge = repo.find_commit(head_id).unwrap();
        let expected_entries = full_tree_blob_entries(&repo, &git_merge.tree().unwrap()).unwrap();
        let mut expected_archive = Vec::new();
        for (path, blob_oid, class) in expected_entries {
            let GitEntryClass::Source(kind) = class else {
                unreachable!("merge fixture contains no submodules");
            };
            expected_archive.push((path, kind, repo.find_blob(blob_oid).unwrap().take_data()));
        }
        let mut replay_archive = Vec::new();
        let mut resolved: Vec<_> = entries.into_iter().collect();
        resolved.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));
        for (path, entry) in resolved {
            replay_archive.push((
                path.0,
                entry.kind,
                blob_store
                    .read(&kin_blobs::Hash256(*entry.hash.as_bytes()))
                    .unwrap(),
            ));
        }
        assert_eq!(replay_archive, expected_archive);
    }

    /// A SemanticChange carrying only an id and parents — enough to exercise the
    /// boundary-parent rewrite without a real Git commit.
    fn bare_change(id: SemanticChangeId, parents: Vec<SemanticChangeId>) -> ImportedChange {
        ImportedChange {
            change: SemanticChange {
                id,
                parents,
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: String::new(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            },
            git_oid: id.to_string(),
        }
    }

    fn cid(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    /// A parent dropped by truncation is re-pointed to genesis; an in-window
    /// parent is left untouched. This is the edge that otherwise dangles and
    /// fails a later `collect_changes_at_ref` history walk.
    #[test]
    fn close_truncated_history_dag_repoints_dangling_parents_to_genesis() {
        let (genesis, a, b, c) = (cid(0x00), cid(0x0A), cid(0x0B), cid(0x0C));
        // Window kept b (parent a) and c (parent b) but dropped a: b's parent is
        // now dangling, c's parent is still present.
        let mut changes = vec![bare_change(b, vec![a]), bare_change(c, vec![b])];
        close_truncated_history_dag(&mut changes, genesis);
        assert_eq!(
            changes[0].change.parents,
            vec![genesis],
            "dangling boundary parent must collapse to genesis"
        );
        assert_eq!(
            changes[1].change.parents,
            vec![b],
            "in-window parent must be preserved"
        );
    }

    /// A merge commit whose parents were both dropped collapses to a single
    /// genesis parent — never a duplicated `[genesis, genesis]`.
    #[test]
    fn close_truncated_history_dag_dedups_collapsed_parents() {
        let (genesis, p1, p2, merge) = (cid(0x00), cid(0x01), cid(0x02), cid(0x0D));
        let mut changes = vec![bare_change(merge, vec![p1, p2])];
        close_truncated_history_dag(&mut changes, genesis);
        assert_eq!(changes[0].change.parents, vec![genesis]);
    }

    /// A complete window (every parent present, root already on genesis) is
    /// untouched — closing only rewrites genuinely dangling edges.
    #[test]
    fn close_truncated_history_dag_is_noop_for_complete_history() {
        let (genesis, root, child) = (cid(0x00), cid(0x0A), cid(0x0B));
        let mut changes = vec![
            bare_change(root, vec![genesis]),
            bare_change(child, vec![root]),
        ];
        let before = format!("{changes:?}");
        close_truncated_history_dag(&mut changes, genesis);
        assert_eq!(
            format!("{changes:?}"),
            before,
            "a self-contained window must be left unchanged"
        );
    }

    /// End-to-end through the real import path: a truncated import must yield a
    /// DAG in which every parent resolves within the imported set ∪ {genesis},
    /// so the oldest imported change can never dangle. Without closing, the
    /// window's boundary commit points at an un-imported Git parent.
    #[test]
    fn truncated_import_produces_closed_dag() {
        let Some(dir) = build_test_repo(12, 4) else {
            eprintln!("git not available, skipping truncated-import closed-DAG test");
            return;
        };
        let repo = open_repo(dir.path()).expect("open repo");
        let head_id = repo
            .head_ref()
            .expect("head_ref")
            .expect("non-empty repo")
            .id()
            .detach();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x66; 32]));

        let full = import_full(&repo, head_id, genesis_id, 0, None).expect("full import");
        assert_eq!(full.len(), 12, "all commits import when max_commits == 0");

        let limited = import_full(&repo, head_id, genesis_id, 5, None).expect("limited import");
        assert_eq!(
            limited.len(),
            5,
            "truncation must keep exactly max_commits changes"
        );

        let imported: HashSet<SemanticChangeId> = limited.iter().map(|ic| ic.change.id).collect();
        for ic in &limited {
            for parent in &ic.change.parents {
                assert!(
                    *parent == genesis_id || imported.contains(parent),
                    "imported change {} has dangling parent {} (neither genesis nor in the imported window)",
                    ic.change.id,
                    parent
                );
            }
        }
    }

    /// Determinism gate: the parallel commit-mapping path must produce a
    /// byte-identical `Vec<ImportedChange>` to the serial reference — same order,
    /// same change_id / parents / artifact_deltas / message / timestamp per
    /// element — and re-running the parallel path must be byte-stable. This is
    /// the proof that parallelizing the import preserves the citable graph.
    #[test]
    fn parallel_import_is_byte_identical_to_serial() {
        let Some(dir) = build_test_repo(40, 6) else {
            eprintln!("git not available, skipping parallel/serial equality test");
            return;
        };

        let repo = open_repo(dir.path()).expect("open repo");
        let head_id = repo
            .head_ref()
            .expect("head_ref")
            .expect("non-empty repo")
            .id()
            .detach();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x44; 32]));

        // Separate blob stores so the comparison isolates the mapping, not store
        // state, and so neither run's writes mask the other's.
        let store_par = BlobStore::new(dir.path().join("blobs-par")).unwrap();
        let store_ser = BlobStore::new(dir.path().join("blobs-ser")).unwrap();

        let parallel = import_full(&repo, head_id, genesis_id, 0, Some(&store_par))
            .expect("parallel import should succeed");
        let serial = import_full_serial(&repo, head_id, genesis_id, 0, Some(&store_ser))
            .expect("serial import should succeed");

        assert!(!parallel.is_empty(), "import should yield changes");
        assert_eq!(
            parallel.len(),
            serial.len(),
            "parallel and serial must import the same number of commits"
        );
        // Debug formatting captures every field (id, parents, timestamp, author,
        // message, artifact_deltas, git_oid); equal Debug strings ⇒ byte-identical
        // ImportedChange vectors in identical order.
        assert_eq!(
            format!("{parallel:?}"),
            format!("{serial:?}"),
            "parallel import must produce byte-identical changes to the serial path"
        );

        // Re-running the parallel path must also be byte-stable.
        let store_par2 = BlobStore::new(dir.path().join("blobs-par2")).unwrap();
        let parallel_again = import_full(&repo, head_id, genesis_id, 0, Some(&store_par2))
            .expect("second parallel import should succeed");
        assert_eq!(
            format!("{parallel:?}"),
            format!("{parallel_again:?}"),
            "parallel import must be byte-stable across runs"
        );

        // The byte-identical guarantee must also hold under max_commits truncation.
        let store_a = BlobStore::new(dir.path().join("blobs-a")).unwrap();
        let store_b = BlobStore::new(dir.path().join("blobs-b")).unwrap();
        let par_limited = import_full(&repo, head_id, genesis_id, 10, Some(&store_a)).unwrap();
        let ser_limited =
            import_full_serial(&repo, head_id, genesis_id, 10, Some(&store_b)).unwrap();
        assert_eq!(par_limited.len(), 10);
        assert_eq!(format!("{par_limited:?}"), format!("{ser_limited:?}"));
    }

    /// Manual timing harness comparing serial vs parallel import over a ~50-commit
    /// temp repo. Ignored by default — run with
    /// `cargo test -p kin-git parallel_import_timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing harness; run explicitly with --ignored --nocapture"]
    fn parallel_import_timing() {
        let num_commits = 50;
        let Some(dir) = build_test_repo(num_commits, 12) else {
            eprintln!("git not available, skipping timing harness");
            return;
        };
        let repo = open_repo(dir.path()).expect("open repo");
        let head_id = repo
            .head_ref()
            .expect("head_ref")
            .expect("non-empty repo")
            .id()
            .detach();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));

        let store_ser = BlobStore::new(dir.path().join("blobs-t-ser")).unwrap();
        let t0 = std::time::Instant::now();
        let serial = import_full_serial(&repo, head_id, genesis_id, 0, Some(&store_ser)).unwrap();
        let serial_ms = t0.elapsed().as_micros() as f64 / 1000.0;

        let store_par = BlobStore::new(dir.path().join("blobs-t-par")).unwrap();
        let t1 = std::time::Instant::now();
        let parallel = import_full(&repo, head_id, genesis_id, 0, Some(&store_par)).unwrap();
        let parallel_ms = t1.elapsed().as_micros() as f64 / 1000.0;

        eprintln!(
            "[import-timing] commits={} serial={serial_ms:.2}ms parallel={parallel_ms:.2}ms \
             speedup={:.2}x",
            serial.len(),
            serial_ms / parallel_ms.max(0.0001)
        );
        assert_eq!(parallel.len(), serial.len());
    }

    fn commit_sha(repo: &Path) -> String {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo)
            .output()
            .expect("git rev-parse HEAD");
        String::from_utf8(output.stdout)
            .expect("utf8 sha")
            .trim()
            .to_string()
    }

    fn commit_file(repo: &Path, name: &str, content: &str, message: &str, epoch: &str) {
        std::fs::write(repo.join(name), content).unwrap();
        let _ = Command::new("git")
            .args(["add", "."])
            .current_dir(repo)
            .output();
        let date = format!("{epoch} +0000");
        let _ = Command::new("git")
            .args(["commit", "-m", message])
            .env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_DATE", &date)
            .current_dir(repo)
            .output();
    }

    #[test]
    fn shallow_boundary_is_a_full_tree_semantic_root_without_missing_parent_anchors() {
        let source = tempfile::tempdir().unwrap();
        if !init_git_repo(source.path()) {
            eprintln!("git not available, skipping shallow-boundary test");
            return;
        }
        commit_file(source.path(), "a.txt", "one\n", "one", "1000000000");
        commit_file(source.path(), "b.txt", "two\n", "two", "1000000100");
        commit_file(source.path(), "a.txt", "three\n", "three", "1000000200");

        let clone_parent = tempfile::tempdir().unwrap();
        let shallow = clone_parent.path().join("shallow");
        let clone = Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                &format!("file://{}", source.path().display()),
                shallow.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            clone.status.success(),
            "shallow clone failed: {}",
            String::from_utf8_lossy(&clone.stderr)
        );

        let genesis = SemanticChangeId::from_hash(Hash256::from_bytes([0xa7; 32]));
        let recent_store = BlobStore::new(clone_parent.path().join("recent-objects")).unwrap();
        let full_store = BlobStore::new(clone_parent.path().join("full-objects")).unwrap();
        let mut recent = import_git_history_with_blobs(
            &shallow,
            genesis,
            &ImportOptions {
                max_commits: 50,
                ..Default::default()
            },
            Some(&recent_store),
        )
        .unwrap();
        let mut full = import_git_history_with_blobs(
            &shallow,
            genesis,
            &ImportOptions::default(),
            Some(&full_store),
        )
        .unwrap();

        assert_eq!(recent.len(), 1);
        assert_eq!(format!("{recent:?}"), format!("{full:?}"));
        assert_eq!(recent[0].change.parents, vec![genesis]);
        assert_eq!(recent[0].change.artifact_deltas.len(), 2);
        assert_eq!(
            anchor_imported_history_at_base_link(
                &shallow,
                &mut recent,
                genesis,
                Some(&recent_store),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            anchor_imported_history_at_base_link(&shallow, &mut full, genesis, Some(&full_store),)
                .unwrap(),
            None
        );
    }

    #[test]
    fn is_ancestor_commit_true_for_direct_ancestor_and_self() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping ancestry test");
            return;
        }

        commit_file(dir.path(), "a.txt", "1\n", "base", "1000000000");
        let base = commit_sha(dir.path());
        commit_file(dir.path(), "a.txt", "2\n", "head", "1000000100");
        let head = commit_sha(dir.path());

        assert_eq!(
            is_ancestor_commit(dir.path(), &base, &head),
            Some(true),
            "base must be reported as an ancestor of head"
        );
        assert_eq!(
            is_ancestor_commit(dir.path(), &head, &base),
            Some(false),
            "head must not be reported as an ancestor of base"
        );
        assert_eq!(
            is_ancestor_commit(dir.path(), &base, &base),
            Some(true),
            "a commit is its own ancestor"
        );
    }

    #[test]
    fn is_ancestor_commit_false_for_unrelated_forked_commits() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping ancestry test");
            return;
        }

        commit_file(dir.path(), "a.txt", "1\n", "root", "1000000000");
        let root = commit_sha(dir.path());

        commit_file(dir.path(), "a.txt", "a\n", "branch a", "1000000100");
        let branch_a = commit_sha(dir.path());

        // Fork a second line of history from `root`, independent of branch a.
        let _ = Command::new("git")
            .args(["checkout", &root])
            .current_dir(dir.path())
            .output();
        commit_file(dir.path(), "a.txt", "b\n", "branch b", "1000000200");
        let branch_b = commit_sha(dir.path());

        assert_eq!(
            is_ancestor_commit(dir.path(), &branch_a, &branch_b),
            Some(false),
            "unrelated forked commits must not be reported as ancestors of each other"
        );
        assert_eq!(is_ancestor_commit(dir.path(), &root, &branch_a), Some(true));
        assert_eq!(is_ancestor_commit(dir.path(), &root, &branch_b), Some(true));
    }

    #[test]
    fn is_ancestor_commit_none_when_a_commit_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping ancestry test");
            return;
        }

        commit_file(dir.path(), "a.txt", "1\n", "root", "1000000000");
        let root = commit_sha(dir.path());
        let absent = "0".repeat(40);

        assert_eq!(
            is_ancestor_commit(dir.path(), &absent, &root),
            None,
            "an absent ancestor commit must report None (undetermined), not a hard failure"
        );
        assert_eq!(
            is_ancestor_commit(dir.path(), &root, &absent),
            None,
            "an absent descendant commit must report None (undetermined), not a hard failure"
        );
    }

    #[test]
    fn is_ancestor_commit_none_when_repo_path_is_not_a_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        let sha = "1111111111111111111111111111111111111111";
        assert_eq!(is_ancestor_commit(dir.path(), sha, sha), None);
    }

    #[test]
    fn expand_git_commit_prefix_unique_absent_and_too_short() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping prefix expansion test");
            return;
        }

        commit_file(dir.path(), "a.txt", "1\n", "base", "1000000000");
        let full = commit_sha(dir.path());

        match expand_git_commit_prefix(dir.path(), &full[..8]) {
            GitOidPrefixExpansion::Commit(expanded) => assert_eq!(
                expanded, full,
                "a unique prefix must expand to its full commit id"
            ),
            other => panic!("unique prefix must expand to a commit, got {:?}", other),
        }
        assert_eq!(
            expand_git_commit_prefix(dir.path(), "deadbeef"),
            GitOidPrefixExpansion::NotFound,
            "a prefix matching no object must report NotFound"
        );
        assert_eq!(
            expand_git_commit_prefix(dir.path(), "abc"),
            GitOidPrefixExpansion::NotFound,
            "prefixes below git's 4-character minimum never expand"
        );
    }

    #[test]
    fn expand_git_commit_prefix_outside_a_repo_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            expand_git_commit_prefix(dir.path(), "deadbeef"),
            GitOidPrefixExpansion::NotFound
        );
    }

    #[test]
    fn expand_git_commit_prefix_reports_ambiguity() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping prefix ambiguity test");
            return;
        }

        commit_file(dir.path(), "a.txt", "1\n", "base", "1000000000");

        // Two loose-object entries sharing the 8-hex prefix `aabbccdd`; prefix
        // lookup disambiguates on object ids (file names), so placeholder
        // contents are enough to make the prefix ambiguous.
        let loose_dir = dir.path().join(".git/objects/aa");
        std::fs::create_dir_all(&loose_dir).unwrap();
        std::fs::write(
            loose_dir.join("bbccdd00000000000000000000000000000001"),
            b"placeholder",
        )
        .unwrap();
        std::fs::write(
            loose_dir.join("bbccdd00000000000000000000000000000002"),
            b"placeholder",
        )
        .unwrap();

        assert_eq!(
            expand_git_commit_prefix(dir.path(), "aabbccdd"),
            GitOidPrefixExpansion::Ambiguous,
            "two objects sharing a prefix must report Ambiguous"
        );
    }
}
