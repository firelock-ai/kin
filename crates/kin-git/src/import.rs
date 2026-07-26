// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use chrono::TimeZone;
use kin_blobs::BlobStore;
use kin_model::{
    ArtifactId, AuthorId, BranchName, GitObjectId, Hash256, LocatedEntry, RepoPath, ResolvedTree,
    SemanticChange, SemanticChangeId, Timestamp, TreeDelta, TreeEntry,
};
use sha2::{Digest, Sha256};
use tracing::{debug, info};
use uuid::Uuid;

use crate::error::{GitError, Result};

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

/// The two canonical ways to introduce an existing Git repository into Kin.
///
/// A snapshot is an exact current-tree boundary with no historical claims. A
/// full import preserves every reachable Git parent edge. There is deliberately
/// no bounded-history mode: mapping the same Git commit to different parents,
/// deltas, or artifact identities based on a window would violate immutable
/// graph authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GitImportMode {
    Snapshot,
    #[default]
    Full,
}

/// Options for importing a Git repository into Kin.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    pub mode: GitImportMode,
    /// Branch to import from (default: HEAD).
    pub branch: Option<String>,
}

/// A Git commit or snapshot mapped to Kin's domain before graph insertion.
#[derive(Debug, Clone)]
pub struct ImportedChange {
    pub change: SemanticChange,
    /// Original Git commit hash for provenance.
    pub git_oid: String,
}

/// One exact first-parent-relative Git tree transition before artifact identity
/// is assigned.
#[derive(Debug, Clone)]
pub(crate) struct CommitFileDelta {
    pub path: RepoPath,
    /// Prior side of the transition. A file or symlink carries a blob id; a
    /// gitlink carries the pinned commit id.
    pub old: Option<(gix::ObjectId, GitEntryClass)>,
    pub new: Option<(gix::ObjectId, GitEntryClass)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitEntryClass {
    Blob { executable: bool },
    Symlink,
    Gitlink,
}

fn update_oid_identity(hasher: &mut Sha256, oid: &gix::ObjectId) {
    hasher.update([oid.as_bytes().len() as u8]);
    hasher.update(oid.as_bytes());
}

/// Compute the canonical full-history SemanticChangeId for a Git commit.
fn change_id_from_git_oid(oid: &gix::ObjectId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.git.semantic-change.v2\0");
    update_oid_identity(&mut hasher, oid);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

/// Snapshot IDs use a separate domain because the same Git commit imported as
/// full history has different parents and deltas.
fn snapshot_change_id_from_git_oid(oid: &gix::ObjectId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.git.snapshot-change.v1\0");
    update_oid_identity(&mut hasher, oid);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

/// Allocate a stable graph identity for one Git introduction event.
///
/// The identity is derived from the immutable source event plus the canonical
/// ordinal of the introduced entry. A path remains a mutable location and is
/// never used as an identity seed. UUID version/variant bits are set so the
/// value remains a well-formed opaque ArtifactId.
fn imported_artifact_id(
    domain: &[u8],
    commit_oid: &gix::ObjectId,
    introduction_ordinal: usize,
) -> ArtifactId {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    update_oid_identity(&mut hasher, commit_oid);
    hasher.update((introduction_ordinal as u64).to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ArtifactId(Uuid::from_bytes(bytes))
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

/// Compute the canonical full-history SemanticChangeId for a Git commit hash.
pub fn semantic_change_id_from_git_oid_hex(oid_hex: &str) -> Result<SemanticChangeId> {
    let oid = gix::ObjectId::from_hex(oid_hex.as_bytes())
        .map_err(|error| GitError::Git(format!("invalid git oid {oid_hex:?}: {error}")))?;
    Ok(change_id_from_git_oid(&oid))
}

pub fn import_git_history(
    repo_path: &Path,
    genesis_id: SemanticChangeId,
    opts: &ImportOptions,
) -> Result<Vec<ImportedChange>> {
    import_git_history_with_blobs(repo_path, genesis_id, opts, None)
}

/// Import either an exact current snapshot or exact full reachable history.
pub fn import_git_history_with_blobs(
    repo_path: &Path,
    genesis_id: SemanticChangeId,
    opts: &ImportOptions,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let _span = tracing::info_span!(
        "kin.git.import",
        repo = %repo_path.display(),
        mode = ?opts.mode,
        has_branch = opts.branch.is_some(),
        blobs = blob_store.is_some()
    )
    .entered();
    let repo = open_repo(repo_path).map_err(|error| GitError::Git(error.to_string()))?;
    let head_ref = if let Some(branch) = &opts.branch {
        repo.find_reference(&format!("refs/heads/{branch}"))
            .map_err(|error| GitError::BranchNotFound(format!("{branch}: {error}")))?
    } else {
        repo.head_ref()
            .map_err(|error| GitError::Git(error.to_string()))?
            .ok_or(GitError::EmptyRepository)?
    };
    let head_id = head_ref.id().detach();

    match opts.mode {
        GitImportMode::Snapshot => import_snapshot(&repo, head_id, genesis_id, blob_store),
        GitImportMode::Full => import_full(&repo, head_id, genesis_id, blob_store),
    }
}

/// Import the complete ancestry reachable from a specific Git commit.
pub fn import_git_history_to_commit_with_blobs(
    repo_path: &Path,
    git_oid_hex: &str,
    genesis_id: SemanticChangeId,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let repo = open_repo(repo_path).map_err(|error| GitError::Git(error.to_string()))?;
    let target_id = gix::ObjectId::from_hex(git_oid_hex.as_bytes())
        .map_err(|error| GitError::Git(format!("invalid git oid {git_oid_hex:?}: {error}")))?;
    repo.find_commit(target_id)
        .map_err(|error| GitError::CommitNotFound(format!("{git_oid_hex}: {error}")))?;
    import_full(&repo, target_id, genesis_id, blob_store)
}

fn commit_metadata(commit: &gix::Commit<'_>) -> Result<(AuthorId, Timestamp, String)> {
    let oid = commit.id;
    let author_sig = commit
        .author()
        .map_err(|error| GitError::Git(error.to_string()))?;
    let author = AuthorId::new(format!("{} <{}>", author_sig.name, author_sig.email));
    let git_time = author_sig
        .time()
        .map_err(|error| GitError::Git(error.to_string()))?;
    let timestamp = timestamp_from_git_seconds(git_time.seconds, &oid)?;
    let message = commit
        .message_raw()
        .map_err(|error| GitError::Git(error.to_string()))?
        .to_string();
    Ok((author, timestamp, message))
}

fn import_snapshot(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    genesis_id: SemanticChangeId,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let commit = repo
        .find_commit(head_id)
        .map_err(|error| GitError::CommitNotFound(format!("{head_id}: {error}")))?;
    let raw_deltas = full_tree_file_deltas(repo, &commit)?;
    let (tree_deltas, _) = materialize_tree_deltas(
        repo,
        head_id,
        &ResolvedTree::default(),
        &[],
        raw_deltas,
        b"kin.git.snapshot-artifact.v1",
        blob_store,
    )?;
    let (author, timestamp, message) = commit_metadata(&commit)?;
    let change = SemanticChange {
        id: snapshot_change_id_from_git_oid(&head_id),
        parents: vec![genesis_id],
        timestamp,
        author,
        message,
        entity_deltas: vec![],
        relation_deltas: vec![],
        tree_deltas,
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: Some(BranchName::new("main")),
    };
    info!(git_oid = %head_id, kin_id = %change.id, "imported exact Git snapshot");
    Ok(vec![ImportedChange {
        change,
        git_oid: head_id.to_string(),
    }])
}

/// Import complete reachable history in deterministic parent-first order.
fn import_full(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    genesis_id: SemanticChangeId,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
    let shallow_boundaries = shallow_boundary_ids(repo)?;
    if !shallow_boundaries.is_empty() {
        return Err(GitError::Other(
            "full Git import requires complete reachable ancestry, but the source repository is shallow; unshallow it or use snapshot mode"
                .to_string(),
        ));
    }

    let walk = repo
        .rev_walk([head_id])
        .all()
        .map_err(|error| GitError::Git(error.to_string()))?;
    let selected = walk
        .map(|step| {
            step.map(|info| info.id().detach())
                .map_err(|error| GitError::Git(error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    let oids = order_selected_oids_parent_first(repo, selected)?;

    let mut states = HashMap::<gix::ObjectId, ResolvedTree>::with_capacity(oids.len());
    let mut changes = Vec::with_capacity(oids.len());
    for oid in oids {
        let commit = repo
            .find_commit(oid)
            .map_err(|error| GitError::CommitNotFound(format!("{oid}: {error}")))?;
        let git_parents = commit
            .parent_ids()
            .map(|parent| parent.detach())
            .collect::<Vec<_>>();
        let parents = if git_parents.is_empty() {
            vec![genesis_id]
        } else {
            git_parents.iter().map(change_id_from_git_oid).collect()
        };
        let base_state = match git_parents.first() {
            Some(parent) => states.get(parent).cloned().ok_or_else(|| {
                GitError::Git(format!(
                    "Git parent {parent} was not resolved before child {oid}"
                ))
            })?,
            None => ResolvedTree::default(),
        };
        let secondary_states = git_parents
            .iter()
            .skip(1)
            .map(|parent| {
                states.get(parent).ok_or_else(|| {
                    GitError::Git(format!(
                        "Git merge parent {parent} was not resolved before child {oid}"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let raw_deltas = if git_parents.is_empty() {
            full_tree_file_deltas(repo, &commit)?
        } else {
            commit_file_deltas(repo, &commit)?
        };
        let (tree_deltas, resolved) = materialize_tree_deltas(
            repo,
            oid,
            &base_state,
            &secondary_states,
            raw_deltas,
            b"kin.git.full-artifact.v1",
            blob_store,
        )?;
        let (author, timestamp, message) = commit_metadata(&commit)?;
        let change = SemanticChange {
            id: change_id_from_git_oid(&oid),
            parents,
            timestamp,
            author,
            message,
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: git_parents.is_empty().then(|| BranchName::new("main")),
        };
        debug!(
            git_oid = %oid,
            kin_id = %change.id,
            parents = change.parents.len(),
            artifacts = resolved.len(),
            "imported Git commit"
        );
        states.insert(oid, resolved);
        changes.push(ImportedChange {
            change,
            git_oid: oid.to_string(),
        });
    }
    info!(count = changes.len(), "full Git history import complete");
    Ok(changes)
}

fn classify_git_entry(mode: gix::objs::tree::EntryMode) -> Option<GitEntryClass> {
    use gix::objs::tree::EntryKind;

    match mode.kind() {
        EntryKind::Blob => Some(GitEntryClass::Blob { executable: false }),
        EntryKind::BlobExecutable => Some(GitEntryClass::Blob { executable: true }),
        EntryKind::Link => Some(GitEntryClass::Symlink),
        EntryKind::Tree => None,
        EntryKind::Commit => Some(GitEntryClass::Gitlink),
    }
}

fn repo_path(bytes: &[u8]) -> Result<RepoPath> {
    RepoPath::from_bytes(bytes.to_vec()).map_err(|error| {
        GitError::Other(format!(
            "invalid Git repository path {}: {error}",
            hex::encode(bytes)
        ))
    })
}

fn git_object_id(oid: gix::ObjectId) -> Result<GitObjectId> {
    match oid.as_bytes() {
        bytes if bytes.len() == 20 => {
            let mut exact = [0u8; 20];
            exact.copy_from_slice(bytes);
            Ok(GitObjectId::sha1(exact))
        }
        bytes if bytes.len() == 32 => {
            let mut exact = [0u8; 32];
            exact.copy_from_slice(bytes);
            Ok(GitObjectId::sha256(exact))
        }
        bytes => Err(GitError::Git(format!(
            "unsupported Git object id width: {} bytes",
            bytes.len()
        ))),
    }
}

fn exact_tree_entry(
    repo: &gix::Repository,
    oid: gix::ObjectId,
    class: GitEntryClass,
    blob_store: Option<&BlobStore>,
) -> Result<TreeEntry> {
    match class {
        GitEntryClass::Blob { executable } => Ok(TreeEntry::blob(
            blob_hash(repo, oid, blob_store)?,
            executable,
        )),
        GitEntryClass::Symlink => Ok(TreeEntry::symlink(blob_hash(repo, oid, blob_store)?)),
        GitEntryClass::Gitlink => Ok(TreeEntry::gitlink(git_object_id(oid)?)),
    }
}

fn materialize_tree_deltas(
    repo: &gix::Repository,
    commit_oid: gix::ObjectId,
    base_state: &ResolvedTree,
    secondary_states: &[&ResolvedTree],
    mut raw_deltas: Vec<CommitFileDelta>,
    identity_domain: &[u8],
    blob_store: Option<&BlobStore>,
) -> Result<(Vec<TreeDelta>, ResolvedTree)> {
    raw_deltas.sort_by(|left, right| left.path.cmp(&right.path));
    let mut deltas = Vec::with_capacity(raw_deltas.len());

    for (ordinal, raw) in raw_deltas.into_iter().enumerate() {
        let old = raw
            .old
            .map(|(oid, class)| {
                exact_tree_entry(repo, oid, class, blob_store)
                    .map(|entry| LocatedEntry::new(raw.path.clone(), entry))
            })
            .transpose()?;
        let new = raw
            .new
            .map(|(oid, class)| {
                exact_tree_entry(repo, oid, class, blob_store)
                    .map(|entry| LocatedEntry::new(raw.path.clone(), entry))
            })
            .transpose()?;

        let delta = match (old, new) {
            (None, Some(new)) => {
                if base_state.artifact_at_path(&new.path).is_some() {
                    return Err(GitError::Other(format!(
                        "Git addition at {} collides with the first-parent tree",
                        new.path
                    )));
                }
                let inherited = secondary_artifact_identity(base_state, secondary_states, &new);
                TreeDelta::Added {
                    artifact_id: inherited.unwrap_or_else(|| {
                        imported_artifact_id(identity_domain, &commit_oid, ordinal)
                    }),
                    new,
                }
            }
            (Some(old), None) => {
                let current = base_state.artifact_at_path(&old.path).ok_or_else(|| {
                    GitError::Other(format!(
                        "Git deletion at {} has no first-parent artifact",
                        old.path
                    ))
                })?;
                if current.entry != old.entry {
                    return Err(GitError::Other(format!(
                        "Git deletion at {} disagrees with the resolved first-parent entry",
                        old.path
                    )));
                }
                TreeDelta::Removed {
                    artifact_id: current.artifact_id,
                    old,
                }
            }
            (Some(old), Some(new)) => {
                let current = base_state.artifact_at_path(&old.path).ok_or_else(|| {
                    GitError::Other(format!(
                        "Git update at {} has no first-parent artifact",
                        old.path
                    ))
                })?;
                if current.entry != old.entry {
                    return Err(GitError::Other(format!(
                        "Git update at {} disagrees with the resolved first-parent entry",
                        old.path
                    )));
                }
                TreeDelta::Updated {
                    artifact_id: current.artifact_id,
                    old,
                    new,
                }
            }
            (None, None) => continue,
        };
        deltas.push(delta);
    }

    let resolved = base_state
        .apply(&deltas)
        .map_err(|error| GitError::Other(format!("invalid imported tree transaction: {error}")))?;
    Ok((deltas, resolved))
}

/// Reuse a secondary-parent identity only when the exact entry appears at the
/// same path under one unambiguous identity and that identity is absent from
/// the first-parent state. Otherwise the merge introduces a new artifact.
fn secondary_artifact_identity(
    base_state: &ResolvedTree,
    secondary_states: &[&ResolvedTree],
    new: &LocatedEntry,
) -> Option<ArtifactId> {
    let mut candidate = None;
    for state in secondary_states {
        let artifact = state.artifact_at_path(&new.path)?;
        if artifact.entry != new.entry || base_state.get(&artifact.artifact_id).is_some() {
            return None;
        }
        match candidate {
            None => candidate = Some(artifact.artifact_id),
            Some(existing) if existing == artifact.artifact_id => {}
            Some(_) => return None,
        }
    }
    candidate
}

fn full_tree_file_deltas(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
) -> Result<Vec<CommitFileDelta>> {
    let tree = commit
        .tree()
        .map_err(|error| GitError::Git(error.to_string()))?;
    full_tree_entries(repo, &tree).map(|entries| {
        entries
            .into_iter()
            .map(|(path, oid, class)| CommitFileDelta {
                path,
                old: None,
                new: Some((oid, class)),
            })
            .collect()
    })
}

fn full_tree_entries(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
) -> Result<Vec<(RepoPath, gix::ObjectId, GitEntryClass)>> {
    let options = gix::diff::Options::default().with_rewrites(None);
    let changes = repo
        .diff_tree_to_tree(None, Some(tree), Some(options))
        .map_err(|error| GitError::Git(error.to_string()))?;
    let mut entries = Vec::new();
    for change in changes {
        if let gix::object::tree::diff::ChangeDetached::Addition {
            location,
            entry_mode,
            id,
            ..
        } = change
        {
            if let Some(class) = classify_git_entry(entry_mode) {
                entries.push((repo_path(location.as_ref())?, id, class));
            }
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

pub(crate) fn commit_file_deltas(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
) -> Result<Vec<CommitFileDelta>> {
    let tree = commit
        .tree()
        .map_err(|error| GitError::Git(error.to_string()))?;
    let parent_tree = commit
        .parent_ids()
        .next()
        .map(|parent_id| {
            repo.find_commit(parent_id.detach())
                .map_err(|error| GitError::Git(error.to_string()))?
                .tree()
                .map_err(|error| GitError::Git(error.to_string()))
        })
        .transpose()?;
    let options = gix::diff::Options::default().with_rewrites(None);
    let changes = repo
        .diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(options))
        .map_err(|error| GitError::Git(error.to_string()))?;
    let mut deltas = Vec::new();
    for change in changes {
        match change {
            gix::object::tree::diff::ChangeDetached::Addition {
                location,
                entry_mode,
                id,
                ..
            } => {
                if let Some(class) = classify_git_entry(entry_mode) {
                    deltas.push(CommitFileDelta {
                        path: repo_path(location.as_ref())?,
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
                if let Some(class) = classify_git_entry(entry_mode) {
                    deltas.push(CommitFileDelta {
                        path: repo_path(location.as_ref())?,
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
                let old = classify_git_entry(previous_entry_mode).map(|class| (previous_id, class));
                let new = classify_git_entry(entry_mode).map(|class| (id, class));
                if old.is_some() || new.is_some() {
                    deltas.push(CommitFileDelta {
                        path: repo_path(location.as_ref())?,
                        old,
                        new,
                    });
                }
            }
            _ => {}
        }
    }
    deltas.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(deltas)
}

fn blob_hash(
    repo: &gix::Repository,
    blob_id: gix::ObjectId,
    blob_store: Option<&BlobStore>,
) -> Result<Hash256> {
    let mut blob = repo
        .find_blob(blob_id)
        .map_err(|error| GitError::Git(error.to_string()))?;
    let content = blob.take_data();
    if let Some(store) = blob_store {
        store.write(&content)?;
    }
    Ok(Hash256::from_bytes(kin_blobs::digest(&content).0))
}

/// Order a selected commit set so every in-set parent precedes its children.
fn order_selected_oids_parent_first(
    repo: &gix::Repository,
    selected: Vec<gix::ObjectId>,
) -> Result<Vec<gix::ObjectId>> {
    let selected_set: HashSet<_> = selected.iter().copied().collect();
    if selected_set.len() != selected.len() {
        return Err(GitError::Git(
            "history walk returned a duplicate commit id".to_string(),
        ));
    }
    let mut indegree: HashMap<_, usize> = selected.iter().copied().map(|oid| (oid, 0)).collect();
    let mut children = BTreeMap::<gix::ObjectId, BTreeSet<gix::ObjectId>>::new();
    for &oid in &selected {
        let commit = repo
            .find_commit(oid)
            .map_err(|error| GitError::Git(error.to_string()))?;
        let selected_parents = commit
            .parent_ids()
            .map(|parent| parent.detach())
            .filter(|parent| selected_set.contains(parent))
            .collect::<BTreeSet<_>>();
        indegree.insert(oid, selected_parents.len());
        for parent in selected_parents {
            children.entry(parent).or_default().insert(oid);
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(oid, degree)| (*degree == 0).then_some(*oid))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(selected.len());
    while let Some(oid) = ready.iter().next().copied() {
        ready.remove(&oid);
        ordered.push(oid);
        if let Some(commit_children) = children.get(&oid) {
            for child in commit_children {
                let degree = indegree
                    .get_mut(child)
                    .expect("selected child has an indegree");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(*child);
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

/// Deterministically select a HEAD-rooted history window for co-change
/// enrichment. This does not create semantic history and is not an authority
/// path.
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
    if max_commits == 0 {
        let mut all = commit_times
            .into_iter()
            .map(|(oid, time)| (Reverse(time), oid))
            .collect::<Vec<_>>();
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
            .find_commit(oid)
            .map_err(|error| GitError::Git(error.to_string()))?;
        for parent in commit.parent_ids().map(|parent| parent.detach()) {
            if let Some(time) = commit_times.get(&parent).copied() {
                frontier.insert((Reverse(time), parent));
            }
        }
    }
    Ok(selected)
}

/// Bounded co-change selection without retaining the complete history walk.
pub(crate) fn select_bounded_history_oids_from_head(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    max_commits: usize,
) -> Result<Vec<gix::ObjectId>> {
    debug_assert!(max_commits > 0);
    let commit_time = |oid| -> Result<i64> {
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
        if selected.len() == max_commits || shallow_boundaries.contains(&oid) {
            continue;
        }
        let commit = repo
            .find_commit(oid)
            .map_err(|error| GitError::CommitNotFound(format!("{oid}: {error}")))?;
        for parent in commit.parent_ids().map(|parent| parent.detach()) {
            if !selected_set.contains(&parent) {
                frontier.insert((Reverse(commit_time(parent)?), parent));
            }
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn init_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-b", "main"]);
        dir
    }

    fn genesis() -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]))
    }

    #[test]
    fn default_import_is_full_history() {
        assert_eq!(ImportOptions::default().mode, GitImportMode::Full);
    }

    #[test]
    fn snapshot_and_full_ids_have_distinct_payload_domains() {
        let dir = init_repo();
        fs::write(dir.path().join("Dockerfile"), b"FROM scratch\n").unwrap();
        git(dir.path(), &["add", "Dockerfile"]);
        git(dir.path(), &["commit", "-m", "root"]);

        let snapshot = import_git_history(
            dir.path(),
            genesis(),
            &ImportOptions {
                mode: GitImportMode::Snapshot,
                branch: None,
            },
        )
        .unwrap();
        let full = import_git_history(dir.path(), genesis(), &ImportOptions::default()).unwrap();

        assert_ne!(snapshot[0].change.id, full[0].change.id);
        assert_eq!(snapshot[0].change.parents, vec![genesis()]);
        assert_eq!(full[0].change.parents, vec![genesis()]);
    }

    #[test]
    fn full_import_preserves_identity_across_content_and_mode_updates() {
        let dir = init_repo();
        let path = dir.path().join("tool");
        fs::write(&path, b"v1\n").unwrap();
        git(dir.path(), &["add", "tool"]);
        git(dir.path(), &["commit", "-m", "add"]);
        fs::write(&path, b"v2\n").unwrap();
        git(dir.path(), &["add", "tool"]);
        git(dir.path(), &["update-index", "--chmod=+x", "tool"]);
        git(dir.path(), &["commit", "-m", "update"]);

        let imported =
            import_git_history(dir.path(), genesis(), &ImportOptions::default()).unwrap();
        assert_eq!(imported.len(), 2);
        let added = imported[0].change.tree_deltas[0].artifact_id();
        let updated = imported[1].change.tree_deltas[0].artifact_id();
        assert_eq!(added, updated);
        assert!(matches!(
            imported[1].change.tree_deltas[0].new_state().unwrap().entry,
            TreeEntry::Blob {
                executable: true,
                ..
            }
        ));
    }

    #[test]
    fn delete_and_readd_allocates_a_new_identity() {
        let dir = init_repo();
        fs::write(dir.path().join("compose.yaml"), b"services: {}\n").unwrap();
        git(dir.path(), &["add", "compose.yaml"]);
        git(dir.path(), &["commit", "-m", "add"]);
        git(dir.path(), &["rm", "compose.yaml"]);
        git(dir.path(), &["commit", "-m", "remove"]);
        fs::write(dir.path().join("compose.yaml"), b"services:\n  app: {}\n").unwrap();
        git(dir.path(), &["add", "compose.yaml"]);
        git(dir.path(), &["commit", "-m", "readd"]);

        let imported =
            import_git_history(dir.path(), genesis(), &ImportOptions::default()).unwrap();
        assert_ne!(
            imported[0].change.tree_deltas[0].artifact_id(),
            imported[2].change.tree_deltas[0].artifact_id()
        );
    }

    #[test]
    fn import_is_byte_stable_across_runs() {
        let dir = init_repo();
        fs::write(dir.path().join("Cargo.lock"), b"version = 4\n").unwrap();
        git(dir.path(), &["add", "Cargo.lock"]);
        git(dir.path(), &["commit", "-m", "lock"]);
        let first = import_git_history(dir.path(), genesis(), &ImportOptions::default()).unwrap();
        let second = import_git_history(dir.path(), genesis(), &ImportOptions::default()).unwrap();
        assert_eq!(
            serde_json::to_vec(&first[0].change).unwrap(),
            serde_json::to_vec(&second[0].change).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_repository_paths_are_preserved_byte_exactly() {
        let dir = init_repo();
        use std::io::Write as _;

        let mut hash_child = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        hash_child
            .stdin
            .take()
            .unwrap()
            .write_all(b"\x00\xffopaque")
            .unwrap();
        let hash_output = hash_child.wait_with_output().unwrap();
        assert!(hash_output.status.success());
        let blob_oid = String::from_utf8(hash_output.stdout).unwrap();

        let raw_path = b"icon-\xff.bin".to_vec();
        let mut tree_child = Command::new("git")
            .args(["mktree", "-z"])
            .current_dir(dir.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut record = format!("100644 blob {}\t", blob_oid.trim()).into_bytes();
        record.extend(&raw_path);
        record.push(0);
        tree_child.stdin.take().unwrap().write_all(&record).unwrap();
        let tree_output = tree_child.wait_with_output().unwrap();
        assert!(tree_output.status.success());
        let tree_oid = String::from_utf8(tree_output.stdout).unwrap();
        let commit = git(
            dir.path(),
            &["commit-tree", tree_oid.trim(), "-m", "non utf8"],
        );
        git(dir.path(), &["update-ref", "refs/heads/main", &commit]);

        let imported =
            import_git_history(dir.path(), genesis(), &ImportOptions::default()).unwrap();
        assert_eq!(
            imported[0].change.tree_deltas[0]
                .new_state()
                .unwrap()
                .path
                .as_bytes(),
            raw_path
        );
    }

    #[test]
    fn merge_reuses_an_unambiguous_secondary_parent_artifact_identity() {
        let dir = init_repo();
        fs::write(dir.path().join("README.md"), b"root\n").unwrap();
        git(dir.path(), &["add", "README.md"]);
        git(dir.path(), &["commit", "-m", "root"]);
        git(dir.path(), &["branch", "right"]);

        fs::write(dir.path().join("left.txt"), b"left\n").unwrap();
        git(dir.path(), &["add", "left.txt"]);
        git(dir.path(), &["commit", "-m", "left"]);

        git(dir.path(), &["switch", "right"]);
        fs::write(dir.path().join("right.txt"), b"right\n").unwrap();
        git(dir.path(), &["add", "right.txt"]);
        git(dir.path(), &["commit", "-m", "right"]);
        let right_oid = git(dir.path(), &["rev-parse", "HEAD"]);

        git(dir.path(), &["switch", "main"]);
        git(dir.path(), &["merge", "--no-ff", "right", "-m", "merge"]);

        let imported =
            import_git_history(dir.path(), genesis(), &ImportOptions::default()).unwrap();
        let right_change = imported
            .iter()
            .find(|change| change.git_oid == right_oid)
            .unwrap();
        let right_id = right_change
            .change
            .tree_deltas
            .iter()
            .find(|delta| {
                delta
                    .new_state()
                    .is_some_and(|entry| entry.path.as_utf8() == Some("right.txt"))
            })
            .unwrap()
            .artifact_id();
        let merge_change = imported.last().unwrap();
        let merged_id = merge_change
            .change
            .tree_deltas
            .iter()
            .find(|delta| {
                delta
                    .new_state()
                    .is_some_and(|entry| entry.path.as_utf8() == Some("right.txt"))
            })
            .unwrap()
            .artifact_id();

        assert_eq!(merged_id, right_id);
        assert_eq!(merge_change.change.parents.len(), 2);
    }

    #[test]
    fn gitlink_is_an_exact_tree_entry() {
        let dir = init_repo();
        let target = "1111111111111111111111111111111111111111";
        let mut child = Command::new("git")
            .args(["mktree"])
            .current_dir(dir.path())
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        writeln!(
            child.stdin.take().unwrap(),
            "160000 commit {target}\tmodule"
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let tree = String::from_utf8(output.stdout).unwrap();
        let commit = git(dir.path(), &["commit-tree", tree.trim(), "-m", "gitlink"]);
        git(dir.path(), &["update-ref", "refs/heads/main", &commit]);

        let imported =
            import_git_history(dir.path(), genesis(), &ImportOptions::default()).unwrap();
        assert!(matches!(
            imported[0].change.tree_deltas[0].new_state().unwrap().entry,
            TreeEntry::Gitlink { .. }
        ));
    }
}
