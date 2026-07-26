// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact graph-tree projection.
//!
//! This module is deliberately separate from semantic `FileLayout` splicing.
//! A layout is optional enrichment for source that Kin can parse; the
//! [`ResolvedTree`] is the complete repository authority for code, config,
//! documentation, assets, unsupported languages, symbolic links, and modes.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kin_blobs::BlobStore;
use kin_model::{ArtifactId, Hash256, RepoPath, ResolvedTree, TreeEntry};

use crate::{ProjectionError, Result};

static TRANSACTION_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// Result of projecting one exact repository tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeProjectionReport {
    /// Target entries whose filesystem representation was published.
    pub materialized: usize,
    /// Previously graph-owned entries removed or displaced by the transition.
    pub removed: usize,
    /// Entries whose target representation already matched the previous tree.
    pub unchanged: usize,
}

#[derive(Debug, Clone)]
struct PlannedEntry {
    _artifact_id: ArtifactId,
    path: RepoPath,
    entry: TreeEntry,
}

#[derive(Debug)]
struct TreePlan {
    by_path: BTreeMap<RepoPath, PlannedEntry>,
}

impl TreePlan {
    fn from_resolved(tree: &ResolvedTree) -> Result<Self> {
        let mut by_path = BTreeMap::new();
        for artifact in tree.artifacts_by_path() {
            // Validate host representability before any staging directory or
            // filesystem object is created. The graph remains byte-exact even
            // when this particular projection host cannot express a path.
            repo_path_to_relative(&artifact.path)?;
            if let TreeEntry::Gitlink { target } = artifact.entry {
                return Err(ProjectionError::UnsupportedGitlink {
                    path: artifact.path.clone(),
                    target,
                });
            }
            by_path.insert(
                artifact.path.clone(),
                PlannedEntry {
                    _artifact_id: artifact.artifact_id,
                    path: artifact.path.clone(),
                    entry: artifact.entry,
                },
            );
        }
        validate_prefix_free(by_path.keys())?;
        Ok(Self { by_path })
    }

    fn len(&self) -> usize {
        self.by_path.len()
    }
}

/// Materialize a graph-owned repository tree into an absent or empty root.
///
/// Every path, entry kind, and blob is staged in a sibling directory before
/// the destination is changed. A non-empty root fails loudly; callers that are
/// moving between graph refs must use [`transition_resolved_tree`] with both
/// exact trees instead of guessing which existing files Kin owns.
pub fn materialize_resolved_tree(
    root: &Path,
    tree: &ResolvedTree,
    blobs: &BlobStore,
) -> Result<TreeProjectionReport> {
    let plan = TreePlan::from_resolved(tree)?;
    let transaction = ProjectionTransaction::stage(root, &plan, blobs)?;

    match fs::symlink_metadata(root) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(transaction.abort(ProjectionError::RootNotDirectory(
                root.display().to_string(),
            )));
        }
        Ok(_) => {
            let mut entries =
                fs::read_dir(root).map_err(|error| transaction.abort(io(root, error)))?;
            if entries
                .next()
                .transpose()
                .map_err(|error| transaction.abort(io(root, error)))?
                .is_some()
            {
                return Err(
                    transaction.abort(ProjectionError::RootNotEmpty(root.display().to_string()))
                );
            }
            fs::remove_dir(root).map_err(|error| transaction.abort(io(root, error)))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(transaction.abort(io(root, error))),
    }

    if let Err(error) = fs::rename(&transaction.stage_root, root) {
        let root_recovery = fs::create_dir(root)
            .map(|_| "recreated empty destination".to_string())
            .unwrap_or_else(|recovery| format!("could not recreate empty destination: {recovery}"));
        let cleanup = transaction.cleanup();
        return Err(ProjectionError::TransactionFailed {
            cause: io(root, error).to_string(),
            rollback: format!("{root_recovery}; {cleanup}"),
        });
    }

    Ok(TreeProjectionReport {
        materialized: plan.len(),
        removed: 0,
        unchanged: 0,
    })
}

/// Reconcile an existing working-copy projection from one exact graph tree to
/// another.
///
/// Only paths owned by `previous` may be displaced. Changed previous entries
/// must still match their graph bytes, kind, and executable bit; unrelated
/// occupants and local edits fail during the read-only preflight. Target bytes
/// are fully staged before any previous entry is moved, which makes swaps,
/// rename cycles, file/directory transitions, and path reuse order-independent.
pub fn transition_resolved_tree(
    root: &Path,
    previous: &ResolvedTree,
    target: &ResolvedTree,
    blobs: &BlobStore,
) -> Result<TreeProjectionReport> {
    ensure_projection_root(root)?;
    let previous = TreePlan::from_resolved(previous)?;
    let target = TreePlan::from_resolved(target)?;

    let affected_previous: BTreeSet<RepoPath> = previous
        .by_path
        .iter()
        .filter(|(path, old)| {
            target
                .by_path
                .get(*path)
                .is_none_or(|new| !same_materialization(old, new))
        })
        .map(|(path, _)| path.clone())
        .collect();
    let target_changes: BTreeSet<RepoPath> = target
        .by_path
        .iter()
        .filter(|(path, new)| {
            previous
                .by_path
                .get(*path)
                .is_none_or(|old| !same_materialization(old, new))
        })
        .map(|(path, _)| path.clone())
        .collect();

    for path in &affected_previous {
        let old = &previous.by_path[path];
        validate_existing_entry(root, old, blobs)?;
    }
    for path in &target_changes {
        validate_target_collision(root, path, &affected_previous)?;
    }

    // Staging the complete target (not merely changed paths) intentionally
    // proves every target blob before the working copy is mutated. This keeps
    // a hidden missing object in an unchanged path from becoming a deferred,
    // branch-dependent failure.
    let transaction = ProjectionTransaction::stage(root, &target, blobs)?;
    let backup_root = transaction.backup_root();
    fs::create_dir(&backup_root).map_err(|error| transaction.abort(io(&backup_root, error)))?;

    let mut displaced = Vec::new();
    let mut published = Vec::new();
    let commit_result = (|| -> Result<()> {
        for path in &affected_previous {
            let relative = repo_path_to_relative(path)?;
            let source = root.join(&relative);
            let backup = backup_root.join(&relative);
            ensure_parent_directories(&backup)?;
            fs::rename(&source, &backup).map_err(|error| io(&source, error))?;
            displaced.push(path.clone());
        }

        remove_empty_ancestors(root, &affected_previous)?;

        for path in &target_changes {
            let relative = repo_path_to_relative(path)?;
            let staged = transaction.stage_root.join(&relative);
            let destination = root.join(&relative);
            ensure_parent_directories(&destination)?;
            remove_empty_directory_at(&destination)?;
            fs::rename(&staged, &destination).map_err(|error| io(&destination, error))?;
            published.push(path.clone());
        }
        Ok(())
    })();

    if let Err(error) = commit_result {
        let rollback = rollback_transition(root, &backup_root, &published, &displaced);
        let cleanup = transaction.cleanup_with_backup(&backup_root);
        return Err(ProjectionError::TransactionFailed {
            cause: error.to_string(),
            rollback: format!("{rollback}; {cleanup}"),
        });
    }

    let backup_cleanup = remove_owned_tree(&backup_root);
    let stage_cleanup = remove_owned_tree(&transaction.stage_root);
    if let Err(error) = backup_cleanup.and(stage_cleanup) {
        return Err(ProjectionError::TransactionFailed {
            cause: "tree projection committed but transaction cleanup failed".to_string(),
            rollback: error.to_string(),
        });
    }

    Ok(TreeProjectionReport {
        materialized: target_changes.len(),
        removed: affected_previous.len(),
        unchanged: target.len().saturating_sub(target_changes.len()),
    })
}

fn ensure_projection_root(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root).map_err(|error| io(root, error))?;
    if !metadata.file_type().is_dir() {
        return Err(ProjectionError::RootNotDirectory(
            root.display().to_string(),
        ));
    }
    Ok(())
}

fn same_materialization(left: &PlannedEntry, right: &PlannedEntry) -> bool {
    left.entry == right.entry
}

fn validate_prefix_free<'a>(paths: impl IntoIterator<Item = &'a RepoPath>) -> Result<()> {
    let paths: Vec<_> = paths.into_iter().collect();
    for pair in paths.windows(2) {
        let ancestor = pair[0].as_bytes();
        let descendant = pair[1].as_bytes();
        if descendant
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
        {
            return Err(ProjectionError::PathConflict {
                ancestor: pair[0].clone(),
                descendant: pair[1].clone(),
            });
        }
    }
    Ok(())
}

struct ProjectionTransaction {
    stage_root: PathBuf,
}

impl ProjectionTransaction {
    fn stage(root: &Path, plan: &TreePlan, blobs: &BlobStore) -> Result<Self> {
        let (parent, sibling_prefix) = projection_parent_and_prefix(root)?;
        let stage_root = unique_sibling_directory(parent, &sibling_prefix, "stage")?;
        let transaction = Self { stage_root };

        let staged = (|| -> Result<()> {
            for entry in plan.by_path.values() {
                stage_entry(&transaction.stage_root, entry, blobs)?;
            }
            sync_directory_tree(&transaction.stage_root)?;
            Ok(())
        })();
        if let Err(error) = staged {
            return Err(transaction.abort(error));
        }
        Ok(transaction)
    }

    fn backup_root(&self) -> PathBuf {
        let parent = self
            .stage_root
            .parent()
            .expect("staging directory always has a parent");
        let mut name = self
            .stage_root
            .file_name()
            .expect("staging directory always has a final component")
            .to_os_string();
        name.push(".backup");
        parent.join(name)
    }

    fn abort(&self, error: ProjectionError) -> ProjectionError {
        let cleanup = self.cleanup();
        if cleanup == "staging removed" {
            error
        } else {
            ProjectionError::TransactionFailed {
                cause: error.to_string(),
                rollback: cleanup,
            }
        }
    }

    fn cleanup(&self) -> String {
        remove_owned_tree(&self.stage_root)
            .map(|_| "staging removed".to_string())
            .unwrap_or_else(|error| format!("staging cleanup failed: {error}"))
    }

    fn cleanup_with_backup(&self, backup: &Path) -> String {
        let stage = remove_owned_tree(&self.stage_root)
            .map(|_| "staging removed".to_string())
            .unwrap_or_else(|error| format!("staging cleanup failed: {error}"));
        let backup = remove_owned_tree(backup)
            .map(|_| "backup removed".to_string())
            .unwrap_or_else(|error| format!("backup cleanup failed: {error}"));
        format!("{stage}; {backup}")
    }
}

fn projection_parent_and_prefix(root: &Path) -> Result<(&Path, OsString)> {
    let parent = root
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            ProjectionError::Other(format!(
                "projection root {} has no usable parent directory",
                root.display()
            ))
        })?;
    let root_name = root.file_name().ok_or_else(|| {
        ProjectionError::Other(format!(
            "projection root {} has no final path component",
            root.display()
        ))
    })?;
    let mut prefix = OsString::from(".");
    prefix.push(root_name);
    prefix.push(".kin-projection");
    Ok((parent, prefix))
}

fn unique_sibling_directory(parent: &Path, prefix: &OsString, role: &str) -> Result<PathBuf> {
    for _ in 0..64 {
        let ordinal = TRANSACTION_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let mut name = prefix.clone();
        name.push(format!(".{role}.{}.{}", std::process::id(), ordinal));
        let candidate = parent.join(name);
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io(&candidate, error)),
        }
    }
    Err(ProjectionError::Other(format!(
        "could not allocate a unique projection {role} directory beneath {}",
        parent.display()
    )))
}

fn stage_entry(root: &Path, entry: &PlannedEntry, blobs: &BlobStore) -> Result<()> {
    let relative = repo_path_to_relative(&entry.path)?;
    let destination = root.join(relative);
    ensure_parent_directories(&destination)?;

    match entry.entry {
        TreeEntry::Blob { hash, executable } => {
            let content = read_tree_blob(blobs, &entry.path, hash)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&destination)
                .map_err(|error| io(&destination, error))?;
            file.write_all(&content)
                .map_err(|error| io(&destination, error))?;
            file.sync_all().map_err(|error| io(&destination, error))?;
            set_executable(&destination, executable)?;
        }
        TreeEntry::Symlink { target_blob } => {
            let target = read_tree_blob(blobs, &entry.path, target_blob)?;
            validate_symlink_target(&entry.path, &target)?;
            create_symlink(&entry.path, &target, &destination)?;
        }
        TreeEntry::Gitlink { target } => {
            return Err(ProjectionError::UnsupportedGitlink {
                path: entry.path.clone(),
                target,
            });
        }
    }
    Ok(())
}

fn read_tree_blob(blobs: &BlobStore, path: &RepoPath, hash: Hash256) -> Result<Vec<u8>> {
    blobs
        .read(&hash)
        .map_err(|error| ProjectionError::TreeBlobUnavailable {
            path: path.clone(),
            hash,
            reason: error.to_string(),
        })
}

fn validate_symlink_target(path: &RepoPath, target: &[u8]) -> Result<()> {
    if target.is_empty() {
        return Err(ProjectionError::InvalidSymlinkTarget {
            path: path.clone(),
            reason: "target is empty".to_string(),
        });
    }
    if target.contains(&0) {
        return Err(ProjectionError::InvalidSymlinkTarget {
            path: path.clone(),
            reason: "target contains NUL".to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn create_symlink(_path: &RepoPath, target: &[u8], destination: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStringExt as _;

    let target = OsString::from_vec(target.to_vec());
    std::os::unix::fs::symlink(PathBuf::from(target), destination)
        .map_err(|error| io(destination, error))
}

#[cfg(not(unix))]
fn create_symlink(path: &RepoPath, _target: &[u8], _destination: &Path) -> Result<()> {
    Err(ProjectionError::SymlinkUnsupported {
        path: path.clone(),
        platform: std::env::consts::OS,
    })
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| io(path, error))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn repo_path_to_relative(path: &RepoPath) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut relative = PathBuf::new();
    for component in path.as_bytes().split(|byte| *byte == b'/') {
        relative.push(OsString::from_vec(component.to_vec()));
    }
    Ok(relative)
}

#[cfg(target_os = "macos")]
fn repo_path_to_relative(path: &RepoPath) -> Result<PathBuf> {
    let utf8 = path
        .as_utf8()
        .ok_or_else(|| ProjectionError::PathUnsupported {
            path: path.clone(),
            platform: std::env::consts::OS,
        })?;
    Ok(utf8.split('/').collect())
}

#[cfg(all(not(unix), not(target_os = "macos")))]
fn repo_path_to_relative(path: &RepoPath) -> Result<PathBuf> {
    let utf8 = path
        .as_utf8()
        .ok_or_else(|| ProjectionError::PathUnsupported {
            path: path.clone(),
            platform: std::env::consts::OS,
        })?;
    if utf8.split('/').any(|component| {
        component.contains('\\')
            || component.contains(':')
            || component.ends_with(' ')
            || component.ends_with('.')
    }) {
        return Err(ProjectionError::PathUnsupported {
            path: path.clone(),
            platform: std::env::consts::OS,
        });
    }
    Ok(utf8.split('/').collect())
}

fn ensure_parent_directories(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    }
    Ok(())
}

fn validate_existing_entry(root: &Path, entry: &PlannedEntry, blobs: &BlobStore) -> Result<()> {
    let relative = repo_path_to_relative(&entry.path)?;
    let path = root.join(relative);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| ProjectionError::LocalModification {
            path: entry.path.clone(),
            reason: error.to_string(),
        })?;

    match entry.entry {
        TreeEntry::Blob { hash, executable } => {
            if !metadata.file_type().is_file() {
                return Err(ProjectionError::LocalModification {
                    path: entry.path.clone(),
                    reason: "expected a regular file".to_string(),
                });
            }
            let expected = read_tree_blob(blobs, &entry.path, hash)?;
            let actual = fs::read(&path).map_err(|error| io(&path, error))?;
            if actual != expected {
                return Err(ProjectionError::LocalModification {
                    path: entry.path.clone(),
                    reason: "file bytes changed".to_string(),
                });
            }
            if executable_bit(&metadata) != executable {
                return Err(ProjectionError::LocalModification {
                    path: entry.path.clone(),
                    reason: "executable bit changed".to_string(),
                });
            }
        }
        TreeEntry::Symlink { target_blob } => {
            if !metadata.file_type().is_symlink() {
                return Err(ProjectionError::LocalModification {
                    path: entry.path.clone(),
                    reason: "expected a symbolic link".to_string(),
                });
            }
            let expected = read_tree_blob(blobs, &entry.path, target_blob)?;
            let actual = read_link_bytes(&path, &entry.path)?;
            if actual != expected {
                return Err(ProjectionError::LocalModification {
                    path: entry.path.clone(),
                    reason: "symbolic-link target changed".to_string(),
                });
            }
        }
        TreeEntry::Gitlink { target } => {
            return Err(ProjectionError::UnsupportedGitlink {
                path: entry.path.clone(),
                target,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn executable_bit(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_bit(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn read_link_bytes(path: &Path, _repo_path: &RepoPath) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;

    fs::read_link(path)
        .map(|target| target.as_os_str().as_bytes().to_vec())
        .map_err(|error| io(path, error))
}

#[cfg(not(unix))]
fn read_link_bytes(_path: &Path, repo_path: &RepoPath) -> Result<Vec<u8>> {
    Err(ProjectionError::SymlinkUnsupported {
        path: repo_path.clone(),
        platform: std::env::consts::OS,
    })
}

fn validate_target_collision(
    root: &Path,
    target: &RepoPath,
    affected_previous: &BTreeSet<RepoPath>,
) -> Result<()> {
    let components: Vec<_> = target.as_bytes().split(|byte| *byte == b'/').collect();
    let mut prefix = Vec::new();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        prefix.extend_from_slice(component);
        let repo_prefix = RepoPath::from_bytes(prefix.clone())
            .expect("components from a validated RepoPath remain valid");
        let path = root.join(repo_path_to_relative(&repo_prefix)?);
        match fs::symlink_metadata(&path) {
            Ok(_) if affected_previous.contains(&repo_prefix) => {}
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(ProjectionError::UntrackedCollision {
                    path: repo_prefix,
                    reason: format!("non-directory ancestor blocks {target}"),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io(&path, error)),
        }
    }

    let destination = root.join(repo_path_to_relative(target)?);
    match fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(&destination, error)),
        Ok(_) if affected_previous.contains(target) => Ok(()),
        Ok(metadata) if metadata.file_type().is_dir() => {
            validate_directory_is_fully_displaced(root, target, affected_previous)
        }
        Ok(_) => Err(ProjectionError::UntrackedCollision {
            path: target.clone(),
            reason: "destination is not owned by the previous graph tree".to_string(),
        }),
    }
}

fn validate_directory_is_fully_displaced(
    root: &Path,
    directory: &RepoPath,
    affected_previous: &BTreeSet<RepoPath>,
) -> Result<()> {
    let path = root.join(repo_path_to_relative(directory)?);
    let mut stack = vec![path];
    while let Some(current) = stack.pop() {
        for child in fs::read_dir(&current).map_err(|error| io(&current, error))? {
            let child = child.map_err(|error| io(&current, error))?;
            let child_path = child.path();
            let metadata =
                fs::symlink_metadata(&child_path).map_err(|error| io(&child_path, error))?;
            if metadata.file_type().is_dir() {
                stack.push(child_path);
                continue;
            }
            let relative = child_path.strip_prefix(root).map_err(|error| {
                ProjectionError::Other(format!(
                    "projection traversal escaped {}: {error}",
                    root.display()
                ))
            })?;
            let repo_path = os_relative_to_repo_path(relative)?;
            if !affected_previous.contains(&repo_path) {
                return Err(ProjectionError::UntrackedCollision {
                    path: repo_path,
                    reason: format!("untracked descendant blocks file projection at {directory}"),
                });
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn os_relative_to_repo_path(path: &Path) -> Result<RepoPath> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut bytes = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(ProjectionError::Other(format!(
                "projection traversal produced non-relative path {}",
                path.display()
            )));
        };
        if !bytes.is_empty() {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(component.as_bytes());
    }
    RepoPath::from_bytes(bytes).map_err(|error| ProjectionError::Other(error.to_string()))
}

#[cfg(not(unix))]
fn os_relative_to_repo_path(path: &Path) -> Result<RepoPath> {
    let path = path.to_str().ok_or_else(|| {
        ProjectionError::Other(format!(
            "host returned an unrepresentable projection path {}",
            path.display()
        ))
    })?;
    RepoPath::from_utf8(path.replace(std::path::MAIN_SEPARATOR, "/"))
        .map_err(|error| ProjectionError::Other(error.to_string()))
}

fn remove_empty_ancestors(root: &Path, paths: &BTreeSet<RepoPath>) -> Result<()> {
    let mut directories = BTreeSet::new();
    for path in paths {
        let relative = repo_path_to_relative(path)?;
        let mut parent = relative.parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    let mut directories: Vec<_> = directories.into_iter().collect();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for relative in directories {
        let directory = root.join(relative);
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => return Err(io(&directory, error)),
        }
    }
    Ok(())
}

fn remove_empty_directory_at(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::remove_dir(path).map_err(|error| io(path, error))
        }
        Ok(_) => Err(ProjectionError::Other(format!(
            "projection destination unexpectedly remained occupied: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(path, error)),
    }
}

fn rollback_transition(
    root: &Path,
    backup_root: &Path,
    published: &[RepoPath],
    displaced: &[RepoPath],
) -> String {
    let mut failures = Vec::new();
    for path in published.iter().rev() {
        let Ok(relative) = repo_path_to_relative(path) else {
            failures.push(format!("could not represent published path {path}"));
            continue;
        };
        let destination = root.join(relative);
        if let Err(error) = remove_leaf(&destination) {
            failures.push(format!("could not remove published {path}: {error}"));
        }
    }
    let displaced_set: BTreeSet<_> = displaced.iter().cloned().collect();
    if let Err(error) = remove_empty_ancestors(root, &displaced_set) {
        failures.push(format!("could not remove publication directories: {error}"));
    }
    for path in displaced {
        let Ok(relative) = repo_path_to_relative(path) else {
            failures.push(format!("could not represent displaced path {path}"));
            continue;
        };
        let source = backup_root.join(&relative);
        let destination = root.join(&relative);
        if let Err(error) = ensure_parent_directories(&destination).and_then(|_| {
            fs::rename(&source, &destination).map_err(|error| io(&destination, error))
        }) {
            failures.push(format!("could not restore {path}: {error}"));
        }
    }
    if failures.is_empty() {
        "restored previous projection".to_string()
    } else {
        failures.join("; ")
    }
}

fn remove_leaf(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::remove_dir(path).map_err(|error| io(path, error))
        }
        Ok(_) => fs::remove_file(path).map_err(|error| io(path, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(path, error)),
    }
}

fn sync_directory_tree(root: &Path) -> Result<()> {
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        for child in fs::read_dir(&directory).map_err(|error| io(&directory, error))? {
            let child = child.map_err(|error| io(&directory, error))?;
            let metadata =
                fs::symlink_metadata(child.path()).map_err(|error| io(child.path(), error))?;
            if metadata.file_type().is_dir() {
                directories.push(child.path());
            }
        }
        index += 1;
    }
    for directory in directories.into_iter().rev() {
        File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| io(&directory, error))?;
    }
    Ok(())
}

fn remove_owned_tree(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::remove_dir_all(path).map_err(|error| io(path, error))
        }
        Ok(_) => fs::remove_file(path).map_err(|error| io(path, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(path, error)),
    }
}

fn io(path: impl AsRef<Path>, source: std::io::Error) -> ProjectionError {
    ProjectionError::io(path, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{GitObjectId, ResolvedArtifact, ResolvedTree};

    fn artifact(path: RepoPath, entry: TreeEntry) -> ResolvedArtifact {
        ResolvedArtifact::new(ArtifactId::new(), path, entry)
    }

    fn path(value: &str) -> RepoPath {
        RepoPath::from_utf8(value).unwrap()
    }

    fn tree(artifacts: impl IntoIterator<Item = ResolvedArtifact>) -> ResolvedTree {
        ResolvedTree::from_artifacts(artifacts).unwrap()
    }

    fn blob_store() -> (tempfile::TempDir, BlobStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = BlobStore::new(directory.path().join("objects")).unwrap();
        (directory, store)
    }

    #[test]
    fn materializes_blob_modes_and_symlink_from_graph_blobs() {
        let (_blob_dir, blobs) = blob_store();
        let regular = blobs.write(b"regular\n").unwrap();
        let executable = blobs.write(b"#!/bin/sh\n").unwrap();
        let target = blobs.write(b"regular.txt").unwrap();
        let tree = tree([
            artifact(path("regular.txt"), TreeEntry::blob(regular, false)),
            artifact(path("bin/run"), TreeEntry::blob(executable, true)),
            artifact(path("current"), TreeEntry::symlink(target)),
        ]);
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");

        let report = materialize_resolved_tree(&root, &tree, &blobs).unwrap();

        assert_eq!(report.materialized, 3);
        assert_eq!(fs::read(root.join("regular.txt")).unwrap(), b"regular\n");
        assert_eq!(fs::read(root.join("bin/run")).unwrap(), b"#!/bin/sh\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(root.join("regular.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
            assert_ne!(
                fs::metadata(root.join("bin/run"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
            assert_eq!(
                fs::read_link(root.join("current")).unwrap(),
                Path::new("regular.txt")
            );
        }
    }

    #[test]
    fn missing_blob_fails_before_an_empty_root_is_changed() {
        let (_blob_dir, blobs) = blob_store();
        let missing = Hash256::from_bytes([0x44; 32]);
        let tree = tree([artifact(
            path("missing.bin"),
            TreeEntry::blob(missing, false),
        )]);
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");
        fs::create_dir(&root).unwrap();

        let error = materialize_resolved_tree(&root, &tree, &blobs).unwrap_err();

        assert!(matches!(
            error,
            ProjectionError::TreeBlobUnavailable { path: failed, .. }
                if failed == path("missing.bin")
        ));
        assert!(root.is_dir());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn gitlink_fails_loudly_before_projection() {
        let (_blob_dir, blobs) = blob_store();
        let target = GitObjectId::sha1([0x55; 20]);
        let tree = tree([artifact(path("vendor/lib"), TreeEntry::gitlink(target))]);
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");

        let error = materialize_resolved_tree(&root, &tree, &blobs).unwrap_err();

        assert!(matches!(
            error,
            ProjectionError::UnsupportedGitlink { path: failed, target: oid }
                if failed == path("vendor/lib") && oid == target
        ));
        assert!(!root.exists());
    }

    #[test]
    fn prefix_conflict_fails_before_projection() {
        let (_blob_dir, blobs) = blob_store();
        let hash = blobs.write(b"x").unwrap();
        let tree = tree([
            artifact(path("a"), TreeEntry::blob(hash, false)),
            artifact(path("a/b"), TreeEntry::blob(hash, false)),
        ]);
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");

        let error = materialize_resolved_tree(&root, &tree, &blobs).unwrap_err();

        assert!(matches!(error, ProjectionError::PathConflict { .. }));
        assert!(!root.exists());
    }

    #[test]
    fn transition_applies_swap_cycle_and_path_reuse_without_order_dependence() {
        let (_blob_dir, blobs) = blob_store();
        let a = blobs.write(b"A").unwrap();
        let b = blobs.write(b"B").unwrap();
        let c = blobs.write(b"C").unwrap();
        let d = blobs.write(b"D").unwrap();
        let left_id = ArtifactId::new();
        let right_id = ArtifactId::new();
        let nested_id = ArtifactId::new();
        let previous = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(left_id, path("a"), TreeEntry::blob(a, false)),
            ResolvedArtifact::new(right_id, path("b"), TreeEntry::blob(b, false)),
            ResolvedArtifact::new(nested_id, path("dir/leaf"), TreeEntry::blob(c, false)),
        ])
        .unwrap();
        let target = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(left_id, path("b"), TreeEntry::blob(a, false)),
            ResolvedArtifact::new(right_id, path("a"), TreeEntry::blob(b, false)),
            ResolvedArtifact::new(nested_id, path("dir"), TreeEntry::blob(d, false)),
        ])
        .unwrap();
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");
        materialize_resolved_tree(&root, &previous, &blobs).unwrap();

        let report = transition_resolved_tree(&root, &previous, &target, &blobs).unwrap();

        assert_eq!(report.materialized, 3);
        assert_eq!(report.removed, 3);
        assert_eq!(fs::read(root.join("a")).unwrap(), b"B");
        assert_eq!(fs::read(root.join("b")).unwrap(), b"A");
        assert_eq!(fs::read(root.join("dir")).unwrap(), b"D");
    }

    #[test]
    fn transition_rejects_local_edits_and_untracked_collisions_before_mutation() {
        let (_blob_dir, blobs) = blob_store();
        let before = blobs.write(b"before").unwrap();
        let after = blobs.write(b"after").unwrap();
        let id = ArtifactId::new();
        let previous = tree([ResolvedArtifact::new(
            id,
            path("tracked"),
            TreeEntry::blob(before, false),
        )]);
        let target = tree([ResolvedArtifact::new(
            id,
            path("other"),
            TreeEntry::blob(after, false),
        )]);
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");
        materialize_resolved_tree(&root, &previous, &blobs).unwrap();
        fs::write(root.join("tracked"), b"local edit").unwrap();
        fs::write(root.join("other"), b"untracked").unwrap();

        let error = transition_resolved_tree(&root, &previous, &target, &blobs).unwrap_err();

        assert!(matches!(error, ProjectionError::LocalModification { .. }));
        assert_eq!(fs::read(root.join("tracked")).unwrap(), b"local edit");
        assert_eq!(fs::read(root.join("other")).unwrap(), b"untracked");
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn non_utf8_paths_and_symlink_targets_are_byte_exact() {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

        let (_blob_dir, blobs) = blob_store();
        let content = blobs.write(&[0, 0xff, 1]).unwrap();
        let target_bytes = b"asset-\xfe.bin";
        let target = blobs.write(target_bytes).unwrap();
        let byte_path = RepoPath::from_bytes(b"asset-\xff.bin".to_vec()).unwrap();
        let link_path = RepoPath::from_bytes(b"link-\xfd".to_vec()).unwrap();
        let tree = tree([
            artifact(byte_path.clone(), TreeEntry::blob(content, false)),
            artifact(link_path.clone(), TreeEntry::symlink(target)),
        ]);
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");

        materialize_resolved_tree(&root, &tree, &blobs).unwrap();

        let file = root.join(OsString::from_vec(byte_path.as_bytes().to_vec()));
        let link = root.join(OsString::from_vec(link_path.as_bytes().to_vec()));
        assert_eq!(fs::read(file).unwrap(), [0, 0xff, 1]);
        assert_eq!(
            fs::read_link(link).unwrap().as_os_str().as_bytes(),
            target_bytes
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn non_utf8_path_fails_typed_before_macos_projection_mutates() {
        let (_blob_dir, blobs) = blob_store();
        let content = blobs.write(&[0, 0xff, 1]).unwrap();
        let byte_path = RepoPath::from_bytes(b"asset-\xff.bin".to_vec()).unwrap();
        let tree = tree([artifact(byte_path.clone(), TreeEntry::blob(content, false))]);
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");

        let error = materialize_resolved_tree(&root, &tree, &blobs).unwrap_err();

        assert!(matches!(
            error,
            ProjectionError::PathUnsupported { path, platform: "macos" }
                if path == byte_path
        ));
        assert!(!root.exists());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn initial_projection_refuses_nonempty_root_without_overwriting() {
        let (_blob_dir, blobs) = blob_store();
        let hash = blobs.write(b"graph").unwrap();
        let tree = tree([artifact(path("tracked"), TreeEntry::blob(hash, false))]);
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("checkout");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("untracked"), b"keep").unwrap();

        let error = materialize_resolved_tree(&root, &tree, &blobs).unwrap_err();

        assert!(matches!(error, ProjectionError::RootNotEmpty(_)));
        assert_eq!(fs::read(root.join("untracked")).unwrap(), b"keep");
        assert!(!root.join("tracked").exists());
    }
}
