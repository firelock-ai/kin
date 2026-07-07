// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::TimeZone;
use kin_blobs::BlobStore;
use kin_model::{
    ArtifactDelta, ArtifactDeltaKind, AuthorId, BranchName, FilePathId, Hash256, SemanticChange,
    SemanticChangeId, Timestamp,
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::error::{GitError, Result};

fn open_repo(path: &Path) -> std::result::Result<gix::Repository, gix::open::Error> {
    let dot_git = path.join(".git");
    if dot_git.is_dir() {
        gix::open(dot_git)
    } else {
        gix::open(path)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CommitFileDelta {
    pub path: String,
    pub old_blob_id: Option<gix::ObjectId>,
    pub new_blob_id: Option<gix::ObjectId>,
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

/// Full history import: walk commits in topological order.
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

    // Walk commits by commit time (approximates parent-before-child order).
    let walk = repo
        .rev_walk([head_id])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(|e| GitError::Git(e.to_string()))?;

    // Phase 1: collect every commit as (commit time, oid), then impose a
    // deterministic total order (time descending, then oid) before honoring
    // max_commits. A raw `ByCommitTime` walk leaves equal-timestamp commits in a
    // process-dependent order, so truncating it — or handing it to the
    // order-sensitive enrichment pass that partitions entity/relation deltas per
    // commit — would select or order the imported commits differently across two
    // preps of identical history. `select_commit_oids` makes the selected set and
    // its order a pure function of commit content, so the per-commit change
    // partition (and every EntityRevisionId/RelationRevisionId derived from an
    // imported change id) is byte-identical run to run. This order is the
    // authority for the final output order.
    let oids: Vec<gix::ObjectId> = {
        let _span = tracing::info_span!("kin.git.import_full.collect_oids").entered();
        let timed: Vec<(i64, gix::ObjectId)> = walk
            .map(|r| {
                r.map(|info| (info.commit_time.unwrap_or(0), info.id().detach()))
                    .map_err(|e| GitError::Git(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        crate::cochange::select_commit_oids(timed, max_commits)
    };

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
                let is_root = commit.parent_ids().count() == 0;
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

    // Reverse so oldest commit is first (topological order).
    changes.reverse();

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

    // Same deterministic (time desc, then oid) selection as `import_full`, so the
    // serial reference stays byte-identical to the parallel path under
    // equal-timestamp ties and `max_commits` truncation.
    let timed: Vec<(i64, gix::ObjectId)> = walk
        .map(|r| {
            r.map(|info| (info.commit_time.unwrap_or(0), info.id().detach()))
                .map_err(|e| GitError::Git(e.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    let oids = crate::cochange::select_commit_oids(timed, max_commits);

    for oid in &oids {
        let commit = repo
            .find_object(*oid)
            .map_err(|e| GitError::Git(e.to_string()))?
            .into_commit();
        let is_root = commit.parent_ids().count() == 0;
        let change = commit_to_change(repo, &commit, genesis_id, is_root, blob_store)?;
        changes.push(ImportedChange {
            change,
            git_oid: oid.to_string(),
        });
    }

    close_truncated_history_dag(&mut changes, genesis_id);

    changes.reverse();
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
    let dt = chrono::Utc
        .timestamp_opt(git_time.seconds, 0)
        .single()
        .unwrap_or_else(chrono::Utc::now);
    let timestamp = Timestamp::from(dt);

    // Extract commit message.
    let message = commit
        .message_raw()
        .map_err(|e| GitError::Git(e.to_string()))?
        .to_string();

    // Compute artifact deltas by examining the commit's tree.
    // For a full import, we'd diff against parent trees. For now, we record
    // file paths from the tree as artifact deltas (the indexing pipeline
    // will later enrich these with entity extraction).
    let artifact_deltas = extract_artifact_deltas(repo, commit, blob_store)?;

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

/// Extract artifact deltas from a commit by diffing against its first parent.
///
/// For root commits (no parents), all files in the tree are "Added".
/// For non-root commits, we diff against the first parent's tree.
fn extract_artifact_deltas(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ArtifactDelta>> {
    let mut deltas = Vec::new();
    for delta in commit_file_deltas(repo, commit)? {
        let kind = match (delta.old_blob_id, delta.new_blob_id) {
            (None, Some(_)) => ArtifactDeltaKind::Added,
            (Some(_), None) => ArtifactDeltaKind::Removed,
            (Some(_), Some(_)) => ArtifactDeltaKind::Modified,
            (None, None) => continue,
        };

        let old_hash = match delta.old_blob_id {
            Some(blob_id) => Some(blob_hash(repo, blob_id, blob_store)?),
            None => None,
        };
        let new_hash = match delta.new_blob_id {
            Some(blob_id) => Some(blob_hash(repo, blob_id, blob_store)?),
            None => None,
        };

        deltas.push(ArtifactDelta {
            file_id: FilePathId::new(delta.path),
            kind,
            old_hash,
            new_hash,
        });
    }

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
            } if entry_mode.is_blob() => deltas.push(CommitFileDelta {
                path: location.to_string(),
                old_blob_id: None,
                new_blob_id: Some(id),
            }),
            gix::object::tree::diff::ChangeDetached::Deletion {
                location,
                entry_mode,
                id,
                ..
            } if entry_mode.is_blob() => deltas.push(CommitFileDelta {
                path: location.to_string(),
                old_blob_id: Some(id),
                new_blob_id: None,
            }),
            gix::object::tree::diff::ChangeDetached::Modification {
                location,
                previous_entry_mode,
                previous_id,
                entry_mode,
                id,
            } if previous_entry_mode.is_blob() || entry_mode.is_blob() => {
                deltas.push(CommitFileDelta {
                    path: location.to_string(),
                    old_blob_id: Some(previous_id),
                    new_blob_id: Some(id),
                })
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

/// Enumerate every blob in a tree as `(path, blob_oid)`, sorted by path.
///
/// Implemented as a diff of the tree against the empty tree (`None`), which
/// yields one Addition per blob — the same machinery `commit_file_deltas` uses
/// for a root commit. The explicit path sort makes the output a pure, stable
/// function of the tree's content, independent of traversal order.
fn full_tree_blob_entries(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
) -> Result<Vec<(String, gix::ObjectId)>> {
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
            if entry_mode.is_blob() {
                entries.push((location.to_string(), id));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

/// Anchor a (possibly truncated) imported history at a synthetic "base-link"
/// change carrying the FULL file universe present at the import window's base.
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
/// This walks the complete Git tree at the window base's first parent — the
/// state the window was built on — and inserts one root change carrying every
/// base file as an Addition (`parents = [genesis_id]`), then re-points the
/// window base's dangling first parent from `genesis_id` to this change. The
/// subsequent semantic-enrichment pass (in `kin-cli`) then parses and links the
/// whole base universe into the base-link change exactly as it does a true root
/// commit, and forks each windowed commit's baseline from it,
/// so every imported head inherits the base-era inbound edges and each commit's
/// delta only records what it actually changed.
///
/// `changes` must be oldest-first, as returned by `import_git_history_*`.
///
/// Returns the inserted base-link change id, or `None` when no anchoring is
/// needed: an empty import, or a full import whose oldest commit is a true Git
/// root (its own artifact deltas already carry the entire tree).
///
/// # Determinism
///
/// The window base is found by a first-parent walk from the newest change (a
/// pure function of the already-deterministic imported DAG). The base id is a
/// hash of the base commit's parent OID. The base-link's artifact deltas are
/// built in sorted-path order with content-addressed blob hashes, and its
/// author/timestamp come from Git commit content, never wall-clock. The output
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

    // Map change id -> slice position so the first-parent walk stays in-set.
    let index_by_id: HashMap<SemanticChangeId, usize> = changes
        .iter()
        .enumerate()
        .map(|(i, ic)| (ic.change.id, i))
        .collect();

    // Window base = the oldest commit reachable from the import head (the newest
    // change, last in oldest-first order) by following the FIRST parent while it
    // stays inside the imported set. `close_truncated_history_dag` has already
    // re-pointed the base's out-of-window first parent to `genesis_id`, so the
    // walk halts there (or at a true root, whose first parent is also genesis).
    let mut cursor = changes.len() - 1;
    loop {
        match changes[cursor].change.parents.first().copied() {
            Some(pid) if pid != genesis_id => match index_by_id.get(&pid) {
                Some(&next) => cursor = next,
                // Dangling parent (should not occur post-close): treat as base.
                None => break,
            },
            // First parent is genesis (re-pointed horizon or true root) or none.
            _ => break,
        }
    }
    let window_base_idx = cursor;

    let repo = open_repo(repo_path).map_err(|e| GitError::Git(e.to_string()))?;

    let base_git_oid = gix::ObjectId::from_hex(changes[window_base_idx].git_oid.as_bytes())
        .map_err(|e| {
            GitError::Git(format!(
                "invalid git oid '{}': {}",
                changes[window_base_idx].git_oid, e
            ))
        })?;
    let base_commit = repo
        .find_commit(base_git_oid)
        .map_err(|e| GitError::CommitNotFound(format!("{base_git_oid}: {e}")))?;

    // The state the window was built on is the base commit's FIRST parent tree.
    // No first parent means this is a true Git root: a full import whose own
    // deltas already carry the whole tree, so there is nothing to anchor.
    let parent_oid = match base_commit.parent_ids().next() {
        Some(pid) => pid.detach(),
        None => return Ok(None),
    };
    let parent_commit = repo
        .find_commit(parent_oid)
        .map_err(|e| GitError::CommitNotFound(format!("{parent_oid}: {e}")))?;
    let parent_tree = parent_commit
        .tree()
        .map_err(|e| GitError::Git(e.to_string()))?;

    // Full base universe as Added artifact deltas, in stable path order. Blobs
    // are materialized into the store so the semantic pass can read and parse
    // them (mirrors how imported commits materialize their changed blobs).
    let entries = full_tree_blob_entries(&repo, &parent_tree)?;
    let mut artifact_deltas = Vec::with_capacity(entries.len());
    for (path, blob_id) in entries {
        let new_hash = blob_hash(&repo, blob_id, blob_store)?;
        artifact_deltas.push(ArtifactDelta {
            file_id: FilePathId::new(path),
            kind: ArtifactDeltaKind::Added,
            old_hash: None,
            new_hash: Some(new_hash),
        });
    }

    // Author/timestamp come from the base parent commit so the synthetic change
    // is a pure function of Git content (no wall-clock), matching how
    // `commit_to_change` derives them for every real imported commit.
    let author_sig = parent_commit
        .author()
        .map_err(|e| GitError::Git(e.to_string()))?;
    let author = AuthorId::new(format!("{} <{}>", author_sig.name, author_sig.email));
    let git_time = author_sig
        .time()
        .map_err(|e| GitError::Git(e.to_string()))?;
    let timestamp = Timestamp::from(
        chrono::Utc
            .timestamp_opt(git_time.seconds, 0)
            .single()
            .unwrap_or_else(chrono::Utc::now),
    );

    let base_id = base_link_change_id_from_git_oid(&parent_oid);
    let base_change = SemanticChange {
        id: base_id,
        parents: vec![genesis_id],
        timestamp,
        author,
        message: "kin import: base-link (window base universe)".to_string(),
        entity_deltas: vec![],   // populated by the semantic enrichment pass
        relation_deltas: vec![], // populated by the semantic enrichment pass
        artifact_deltas,
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: Some(BranchName::new("main")),
    };

    // Re-point the window base's first parent from genesis to the base-link so
    // every head's first-parent ancestry now flows through the base universe.
    if let Some(first) = changes[window_base_idx].change.parents.first_mut() {
        if *first == genesis_id {
            *first = base_id;
        }
    }

    // Prepend: created before its child, and processed first by the topological
    // enrichment pass (its own parent, genesis, is out of the imported set).
    changes.insert(
        0,
        ImportedChange {
            change: base_change,
            git_oid: parent_oid.to_string(),
        },
    );

    Ok(Some(base_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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
    fn different_oids_produce_different_ids() {
        let oid1 = gix::ObjectId::from_hex(b"aabbccddee00112233445566778899aabbccddee").unwrap();
        let oid2 = gix::ObjectId::from_hex(b"00112233445566778899aabbccddeeff00112233").unwrap();
        let id1 = change_id_from_git_oid(&oid1);
        let id2 = change_id_from_git_oid(&oid2);
        assert_ne!(id1, id2);
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
            vec![("alpha.txt".to_string(), ArtifactDeltaKind::Modified)]
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
                ("alpha.txt".to_string(), ArtifactDeltaKind::Added),
                ("beta.txt".to_string(), ArtifactDeltaKind::Added),
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

    /// Determinism regression: two preps of byte-identical history must partition the
    /// same commits into the same imported changes. When every commit shares a
    /// timestamp, the pre-fix `take(max_commits)` over a raw `ByCommitTime` walk
    /// selected a process-dependent subset; the content-addressed
    /// `select_commit_oids` total order must instead pick the same subset — the
    /// `max_commits` smallest oids — and emit it in the same order every run, so
    /// every imported change id (and the entity/relation revision ids derived from
    /// it) is stable across preps.
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

        // Expected truncated selection: the 4 smallest oids (content tie-break),
        // emitted oldest-first — i.e. that ascending set reversed, matching how
        // `import_full` reverses the time-desc/oid-asc order it selects.
        let mut all_oids: Vec<String> = full.iter().map(|c| c.git_oid.clone()).collect();
        all_oids.sort();
        let expected: Vec<String> = all_oids.into_iter().take(4).rev().collect();

        // Two independent truncated imports must both equal the expected set, in
        // the same order — proving the boundary depends on content, not on the
        // walk's (process-dependent) emission order for the tied commits.
        for _ in 0..2 {
            let limited = import_full(&repo, head_id, genesis_id, 4, None).expect("limited import");
            let got_oids: Vec<String> = limited.iter().map(|c| c.git_oid.clone()).collect();
            assert_eq!(
                got_oids, expected,
                "equal-timestamp truncation must select the oid-deterministic subset"
            );
            let got_ids: Vec<String> = limited.iter().map(|c| c.change.id.to_string()).collect();
            let expected_ids: Vec<String> = expected
                .iter()
                .map(|oid| {
                    semantic_change_id_from_git_oid_hex(oid)
                        .expect("valid oid")
                        .to_string()
                })
                .collect();
            assert_eq!(
                got_ids, expected_ids,
                "imported change ids must be stable across preps"
            );
        }
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
