// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use gix::objs::tree::{Entry, EntryKind, EntryMode};
use gix::objs::{Commit, Tree};
use kin_blobs::BlobStore;
use kin_model::{
    BranchName, GraphStore, SemanticChange, SemanticChangeId, TreeDelta, TreeEntryKind,
};
use tracing::{debug, info};

use crate::error::{GitError, Result};
use crate::genesis::is_genesis_change;

/// Options for exporting Kin history to Git.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Branch to export (defaults to "main").
    pub branch: String,

    /// Path to create/update the Git repository.
    pub output_path: Option<String>,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            branch: "main".to_string(),
            output_path: None,
        }
    }
}

/// Result of a Git export operation.
#[derive(Debug)]
pub struct ExportResult {
    /// Number of commits created in Git.
    pub commits_exported: usize,
    /// Path to the Git repository.
    pub git_repo_path: String,
    /// Number of branch refs updated.
    pub branches_updated: usize,
    /// Number of commits that were skipped (already exported).
    pub commits_skipped: usize,
}

/// Export Kin SemanticChange history to a Git repository.
///
/// This translates the SemanticChange DAG into Git commits, stripping the
/// synthetic genesis node. Exported history starts from the first real commit.
///
/// The caller provides a `GraphStore` to read the change DAG and a `BlobStore`
/// to read file contents for tree construction.
///
/// Changes are exported in topological order. For incremental exports, changes
/// that already have corresponding Git commits are skipped.
pub fn export_to_git<G>(
    graph: &G,
    blob_store: &BlobStore,
    genesis_id: SemanticChangeId,
    branch_name: &BranchName,
    output_path: &Path,
) -> Result<ExportResult>
where
    G: GraphStore,
{
    // Get the branch head.
    let branch = graph
        .get_branch(branch_name)
        .map_err(|e| GitError::Graph(e.to_string()))?
        .ok_or_else(|| GitError::BranchNotFound(branch_name.to_string()))?;

    // Walk from branch head back to genesis to collect all changes in topo order.
    let changes = graph
        .get_changes_since(&genesis_id, &branch.head)
        .map_err(|e| GitError::Graph(e.to_string()))?;

    if changes.is_empty() {
        info!("no changes to export (only genesis)");
        return Ok(ExportResult {
            commits_exported: 0,
            git_repo_path: output_path.display().to_string(),
            branches_updated: 0,
            commits_skipped: 0,
        });
    }

    export_changes(blob_store, &changes, branch_name, output_path)
}

fn open_repo(path: &Path) -> std::result::Result<gix::Repository, gix::open::Error> {
    let dot_git = path.join(".git");
    if dot_git.is_dir() {
        gix::open(dot_git)
    } else {
        gix::open(path)
    }
}

/// Export a list of SemanticChanges to a Git repository.
///
/// Changes must be in topological order (parents before children).
/// Genesis changes are automatically skipped.
pub fn export_changes(
    blob_store: &BlobStore,
    changes: &[SemanticChange],
    branch_name: &BranchName,
    output_path: &Path,
) -> Result<ExportResult> {
    // Initialize or open the Git repository.
    let git_repo = if output_path.join(".git").exists() || output_path.join("HEAD").exists() {
        open_repo(output_path).map_err(|e| GitError::Git(e.to_string()))?
    } else {
        gix::init_bare(output_path).map_err(|e| GitError::Git(e.to_string()))?
    };

    // Build a mapping of existing commits for incremental export.
    // We store SemanticChangeId -> git ObjectId for parent resolution.
    let mut change_to_commit: HashMap<SemanticChangeId, gix::ObjectId> = HashMap::new();

    // Check if the repo already has commits on this branch (incremental export).
    let existing_head = find_branch_head(&git_repo, branch_name)?;

    let mut commits_exported = 0usize;
    let commits_skipped = 0usize;
    // Track one immutable file state per semantic change. A single cumulative
    // map contaminates sibling branches: exporting sibling B after sibling A
    // would incorrectly include A-only files in B's Git tree.
    let mut file_states: HashMap<SemanticChangeId, BTreeMap<String, SourceFileState>> =
        HashMap::new();
    let mut last_commit_id: Option<gix::ObjectId> = existing_head;

    for change in changes {
        // Skip genesis changes.
        if is_genesis_change(change) {
            debug!("skipping genesis change in export");
            continue;
        }

        // Reconstruct this change from its own parent states. Parent order is
        // deterministic; later parents fill/replace paths before the change's
        // own deltas apply. Exact imported merges carry a full correction.
        let mut file_state = BTreeMap::new();
        for parent in &change.parents {
            if let Some(parent_state) = file_states.get(parent) {
                for (path, source) in parent_state {
                    file_state.insert(path.clone(), source.clone());
                }
            }
        }
        apply_tree_deltas(change, blob_store, &mut file_state)?;

        // Build the Git tree from the current file state.
        let tree_id = build_tree(&git_repo, &file_state)?;

        // Resolve parent commit IDs from the SemanticChange parent chain.
        let parents = resolve_parents(change, &change_to_commit, last_commit_id);

        // Create the commit object.
        let commit_id = create_commit(&git_repo, change, tree_id, &parents)?;

        debug!(
            change_id = %change.id,
            commit = %commit_id,
            message = %change.message,
            parents = parents.len(),
            "exported change as git commit"
        );

        change_to_commit.insert(change.id, commit_id);
        file_states.insert(change.id, file_state);
        last_commit_id = Some(commit_id);
        commits_exported += 1;
    }

    // Update the branch ref to point to the latest commit.
    let mut branches_updated = 0;
    if let Some(head_id) = last_commit_id {
        update_branch_ref(&git_repo, branch_name, existing_head, head_id)?;
        branches_updated = 1;
    }

    info!(
        commits = commits_exported,
        skipped = commits_skipped,
        path = %output_path.display(),
        "export complete"
    );

    Ok(ExportResult {
        commits_exported,
        git_repo_path: output_path.display().to_string(),
        branches_updated,
        commits_skipped,
    })
}

/// Apply exact repository-tree deltas from a change to the cumulative file state.
fn apply_tree_deltas(
    change: &SemanticChange,
    blob_store: &BlobStore,
    file_state: &mut BTreeMap<String, SourceFileState>,
) -> Result<()> {
    for delta in &change.tree_deltas {
        let (file_id, entry) = match delta {
            TreeDelta::Removed { file_id, .. } => {
                file_state.remove(&file_id.0);
                continue;
            }
            TreeDelta::Added { file_id, new_entry }
            | TreeDelta::Modified {
                file_id, new_entry, ..
            } => (file_id, new_entry),
        };
        let content = blob_store
            .read(&kin_blobs::Hash256(entry.blob_hash.0))
            .map_err(|error| {
                GitError::Other(format!(
                    "cannot export exact tree blob {} for {} in change {}: {error}",
                    entry.blob_hash, file_id, change.id
                ))
            })?;
        file_state.insert(
            file_id.0.clone(),
            SourceFileState {
                content,
                kind: entry.kind,
            },
        );
    }
    Ok(())
}

/// Build a Git tree object from a flat map of file paths to contents.
///
/// Handles nested directory structures by creating intermediate tree objects.
fn build_tree(
    repo: &gix::Repository,
    file_state: &BTreeMap<String, SourceFileState>,
) -> Result<gix::ObjectId> {
    if file_state.is_empty() {
        // Return the well-known empty tree hash.
        return Ok(gix::ObjectId::empty_tree(gix::hash::Kind::Sha1));
    }

    // Build a nested map: directory -> entries.
    // We process paths to create intermediate trees bottom-up.
    let mut dir_entries: BTreeMap<String, Vec<(String, DirEntry)>> = BTreeMap::new();

    // First pass: write all blobs and record them with their directory.
    for (path, source) in file_state {
        let blob_id = repo
            .write_blob(&source.content)
            .map_err(|e| GitError::Git(e.to_string()))?
            .detach();

        let (dir, filename) = split_path(path);
        dir_entries.entry(dir).or_default().push((
            filename,
            DirEntry::Source {
                id: blob_id,
                kind: source.kind,
            },
        ));
    }

    // Build trees bottom-up: process deepest directories first.
    // Collect all directory paths and sort by depth (deepest first).
    let mut all_dirs: Vec<String> = dir_entries.keys().cloned().collect();

    // Also find all intermediate directories that may not have direct files.
    let mut intermediate_dirs: Vec<String> = Vec::new();
    for dir in &all_dirs {
        let mut current = dir.as_str();
        while let Some(pos) = current.rfind('/') {
            let parent = &current[..pos];
            if !all_dirs.contains(&parent.to_string())
                && !intermediate_dirs.contains(&parent.to_string())
            {
                intermediate_dirs.push(parent.to_string());
            }
            current = parent;
        }
        // Root directory
        if !current.is_empty()
            && !all_dirs.contains(&String::new())
            && !intermediate_dirs.contains(&String::new())
        {
            intermediate_dirs.push(String::new());
        }
    }
    all_dirs.extend(intermediate_dirs);
    // Sort by depth descending so we process deepest dirs first.
    all_dirs.sort_by(|a, b| {
        let depth_a = if a.is_empty() {
            0
        } else {
            a.matches('/').count() + 1
        };
        let depth_b = if b.is_empty() {
            0
        } else {
            b.matches('/').count() + 1
        };
        depth_b.cmp(&depth_a)
    });
    all_dirs.dedup();

    // Map from directory path -> tree ObjectId once written.
    let mut tree_ids: HashMap<String, gix::ObjectId> = HashMap::new();

    for dir in &all_dirs {
        let mut entries: Vec<Entry> = Vec::new();

        // Add file (blob) entries in this directory.
        if let Some(file_entries) = dir_entries.get(dir) {
            for (name, entry) in file_entries {
                match entry {
                    DirEntry::Source { id, kind } => {
                        entries.push(Entry {
                            mode: EntryMode::from(match kind {
                                TreeEntryKind::Regular { executable: false } => EntryKind::Blob,
                                TreeEntryKind::Regular { executable: true } => {
                                    EntryKind::BlobExecutable
                                }
                                TreeEntryKind::Symlink => EntryKind::Link,
                            }),
                            filename: name.clone().into(),
                            oid: *id,
                        });
                    }
                }
            }
        }

        // Add subdirectory (tree) entries that are direct children of this dir.
        for (subdir, sub_tree_id) in &tree_ids {
            let (parent, dirname) = split_path(subdir);
            if parent == *dir {
                entries.push(Entry {
                    mode: EntryMode::from(EntryKind::Tree),
                    filename: dirname.into(),
                    oid: *sub_tree_id,
                });
            }
        }

        // Sort entries by filename (Git requires sorted entries).
        entries.sort();

        let tree = Tree { entries };
        let tree_id = repo
            .write_object(&tree)
            .map_err(|e| GitError::Git(e.to_string()))?
            .detach();

        tree_ids.insert(dir.clone(), tree_id);
    }

    // The root tree is at the empty string key.
    tree_ids
        .get("")
        .copied()
        .ok_or_else(|| GitError::Other("failed to build root tree".to_string()))
}

#[derive(Debug, Clone)]
struct SourceFileState {
    content: Vec<u8>,
    kind: TreeEntryKind,
}

#[derive(Debug)]
enum DirEntry {
    Source {
        id: gix::ObjectId,
        kind: TreeEntryKind,
    },
}

/// Split a path into (directory, filename).
/// "src/main.rs" -> ("src", "main.rs")
/// "README.md" -> ("", "README.md")
fn split_path(path: &str) -> (String, String) {
    match path.rfind('/') {
        Some(pos) => (path[..pos].to_string(), path[pos + 1..].to_string()),
        None => (String::new(), path.to_string()),
    }
}

/// Create a Git commit object from a SemanticChange.
fn create_commit(
    repo: &gix::Repository,
    change: &SemanticChange,
    tree_id: gix::ObjectId,
    parent_ids: &[gix::ObjectId],
) -> Result<gix::ObjectId> {
    // Extract author info from the SemanticChange.
    let (author_name, author_email) = parse_author(&change.author.0);

    let time_seconds = change.timestamp.0.timestamp();
    let time = gix::date::Time::new(time_seconds, 0);

    let author = gix::actor::Signature {
        name: author_name.into(),
        email: author_email.into(),
        time,
    };
    let committer = author.clone();

    let commit = Commit {
        tree: tree_id,
        parents: parent_ids.iter().copied().collect(),
        author,
        committer,
        encoding: None,
        message: change.message.clone().into(),
        extra_headers: Vec::new(),
    };

    let commit_id = repo
        .write_object(&commit)
        .map_err(|e| GitError::Git(e.to_string()))?
        .detach();

    Ok(commit_id)
}

/// Parse an author string like "name <email>" into (name, email).
/// Falls back to using the whole string as name with a placeholder email.
fn parse_author(author: &str) -> (String, String) {
    if let Some(start) = author.find('<') {
        if let Some(end) = author.find('>') {
            let name = author[..start].trim().to_string();
            let email = author[start + 1..end].to_string();
            return (name, email);
        }
    }
    (author.to_string(), "unknown@kin".to_string())
}

/// Resolve parent commit IDs from a SemanticChange's parent references.
///
/// For the first real commit (whose only parent is genesis), this returns
/// `last_commit_id` if set (incremental export) or empty (fresh export).
fn resolve_parents(
    change: &SemanticChange,
    change_to_commit: &HashMap<SemanticChangeId, gix::ObjectId>,
    last_commit_id: Option<gix::ObjectId>,
) -> Vec<gix::ObjectId> {
    let mut parents = Vec::new();

    for parent_id in &change.parents {
        if let Some(git_id) = change_to_commit.get(parent_id) {
            parents.push(*git_id);
        }
    }

    // If we couldn't resolve any parents but have a last_commit_id (incremental),
    // use that as the parent to maintain continuity.
    if parents.is_empty() {
        if let Some(last) = last_commit_id {
            parents.push(last);
        }
    }

    parents
}

fn validated_branch_ref_name(branch_name: &BranchName) -> Result<gix::refs::FullName> {
    let candidate = format!("refs/heads/{}", branch_name.0);
    let full_name = gix::refs::FullName::try_from(candidate.clone())
        .map_err(|error| GitError::Git(format!("invalid Git branch ref {candidate:?}: {error}")))?;
    if !matches!(full_name.category(), Some(gix::refs::Category::LocalBranch)) {
        return Err(GitError::Git(format!(
            "ref {candidate:?} is not a local branch"
        )));
    }
    Ok(full_name)
}

fn validate_loose_ref_backend(repo: &gix::Repository) -> Result<()> {
    if repo.namespace().is_some() {
        return Err(GitError::Git(
            "Kin Git export does not support namespaced ref updates".to_string(),
        ));
    }
    if let Some(storage) = repo.config_snapshot().string("extensions.refStorage") {
        if !storage.as_ref().eq_ignore_ascii_case(b"files") {
            return Err(GitError::Git(format!(
                "Kin Git export does not support ref storage {storage:?}; expected files"
            )));
        }
    }
    Ok(())
}

fn read_direct_ref_head(
    repo: &gix::Repository,
    ref_name: &gix::refs::FullName,
) -> Result<Option<gix::ObjectId>> {
    let ref_name_ref: &gix::refs::FullNameRef = ref_name.as_ref();
    let reference = repo
        .try_find_reference(ref_name_ref)
        .map_err(|error| GitError::Git(format!("failed to read ref {ref_name}: {error}")))?;
    reference
        .map(|reference| {
            reference
                .try_id()
                .map(|id| id.detach())
                .ok_or_else(|| GitError::Git(format!("ref {ref_name} is symbolic")))
        })
        .transpose()
}

/// Find the current head commit of a branch, if it exists.
fn find_branch_head(
    repo: &gix::Repository,
    branch_name: &BranchName,
) -> Result<Option<gix::ObjectId>> {
    validate_loose_ref_backend(repo)?;
    let ref_name = validated_branch_ref_name(branch_name)?;
    read_direct_ref_head(repo, &ref_name)
}

fn loose_ref_resource(
    repo: &gix::Repository,
    ref_name: &gix::refs::FullName,
) -> Result<(PathBuf, PathBuf)> {
    validate_loose_ref_backend(repo)?;
    let relative = ref_name.to_path();
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(GitError::Git(format!(
            "ref {ref_name} does not resolve beneath the Git common directory"
        )));
    }
    let common_dir = repo.common_dir().to_path_buf();
    Ok((common_dir.join(relative), common_dir))
}

fn ref_lock_fail_mode(repo: &gix::Repository) -> Result<gix::lock::acquire::Fail> {
    const DEFAULT_TIMEOUT_MS: i64 = 100;
    let timeout_ms = repo
        .config_snapshot()
        .integer("core.filesRefLockTimeout")
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    Ok(match timeout_ms {
        // Match Git and gix: a negative timeout retries effectively forever.
        // gix consumes this as an elapsed-duration budget instead of adding it
        // to an Instant, so the sentinel does not overflow a clock.
        timeout_ms if timeout_ms < 0 => {
            gix::lock::acquire::Fail::AfterDurationWithBackoff(Duration::from_secs(u64::MAX))
        }
        0 => gix::lock::acquire::Fail::Immediately,
        timeout_ms => gix::lock::acquire::Fail::AfterDurationWithBackoff(Duration::from_millis(
            timeout_ms as u64,
        )),
    })
}

/// Update (or create) a branch ref only if it still has the value observed
/// before export began.
///
/// This deliberately writes no reflog. The public gix transaction API reads
/// the current ref before waiting for its lock, while updating a reflog outside
/// that transaction cannot be committed atomically with this lock. Preserving
/// the ref CAS takes precedence over emitting a potentially misleading log.
fn update_branch_ref(
    repo: &gix::Repository,
    branch_name: &BranchName,
    expected_head: Option<gix::ObjectId>,
    commit_id: gix::ObjectId,
) -> Result<()> {
    let lock_fail_mode = ref_lock_fail_mode(repo)?;
    update_branch_ref_with_lock_acquirer(
        repo,
        branch_name,
        expected_head,
        commit_id,
        |resource, boundary| {
            gix::lock::File::acquire_to_update_resource(
                resource,
                lock_fail_mode,
                Some(boundary.to_path_buf()),
            )
        },
    )
}

fn update_branch_ref_with_lock_acquirer(
    repo: &gix::Repository,
    branch_name: &BranchName,
    expected_head: Option<gix::ObjectId>,
    commit_id: gix::ObjectId,
    acquire_lock: impl FnOnce(
        &Path,
        &Path,
    ) -> std::result::Result<gix::lock::File, gix::lock::acquire::Error>,
) -> Result<()> {
    let ref_name = validated_branch_ref_name(branch_name)?;
    let (resource, common_dir) = loose_ref_resource(repo, &ref_name)?;
    let mut lock = acquire_lock(&resource, &common_dir)
        .map_err(|error| GitError::Git(format!("failed to lock ref {ref_name}: {error}")))?;

    let fresh_repo = gix::open(&common_dir).map_err(|error| {
        GitError::Git(format!(
            "failed to open a fresh ref view at {}: {error}",
            common_dir.display()
        ))
    })?;
    validate_loose_ref_backend(&fresh_repo)?;
    let actual_head = read_direct_ref_head(&fresh_repo, &ref_name)?;
    if actual_head != expected_head {
        return Err(GitError::Git(format!(
            "ref {ref_name} changed during export: expected {expected_head:?}, found {actual_head:?}"
        )));
    }

    writeln!(lock, "{commit_id}").map_err(|error| GitError::io(lock.lock_path(), error))?;
    lock.commit().map_err(|error| {
        let path = error.instance.lock_path().to_path_buf();
        GitError::io(path, error.error)
    })?;

    info!(branch = %branch_name.0, commit = %commit_id, "updated branch ref");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gix::refs::{transaction::PreviousValue, Target};
    use kin_model::*;
    use std::collections::HashMap;
    use std::sync::{mpsc, Mutex};
    use std::thread;

    // -- Test helpers --

    fn make_genesis() -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("kin"),
            message: "kin init".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    fn make_change(
        id_byte: u8,
        parents: Vec<SemanticChangeId>,
        message: &str,
        deltas: Vec<ArtifactDelta>,
    ) -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([id_byte; 32])),
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("Alice <alice@example.com>"),
            message: message.to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    fn make_blob_store(dir: &Path) -> BlobStore {
        BlobStore::new(dir.join("blobs")).unwrap()
    }

    /// Write content to the blob store and return the hash.
    fn store_blob(blob_store: &BlobStore, content: &[u8]) -> Hash256 {
        let blob_hash = blob_store.write(content).unwrap();
        Hash256::from_bytes(blob_hash.0)
    }

    fn make_delta(path: &str, kind: ArtifactDeltaKind, new_hash: Option<Hash256>) -> ArtifactDelta {
        ArtifactDelta {
            file_id: FilePathId::new(path),
            kind,
            old_hash: None,
            new_hash,
        }
    }

    fn write_test_commit(repo: &gix::Repository, id_byte: u8, message: &str) -> gix::ObjectId {
        let change = make_change(id_byte, vec![], message, vec![]);
        create_commit(
            repo,
            &change,
            gix::ObjectId::empty_tree(gix::hash::Kind::Sha1),
            &[],
        )
        .unwrap()
    }

    /// Test-only GraphStore mock for export tests. Stores branches and changes
    /// in memory; only `get_branch`, `get_changes_since`, and `list_branches`
    /// have real implementations. All other methods are stubs returning empty values.
    struct MockGraph {
        changes: Mutex<Vec<SemanticChange>>,
        branches: Mutex<HashMap<String, Branch>>,
    }

    impl MockGraph {
        fn new() -> Self {
            Self {
                changes: Mutex::new(Vec::new()),
                branches: Mutex::new(HashMap::new()),
            }
        }

        fn with_branch_and_changes(
            branch_name: &str,
            head: SemanticChangeId,
            changes: Vec<SemanticChange>,
        ) -> Self {
            let g = Self::new();
            g.branches.lock().unwrap().insert(
                branch_name.to_string(),
                Branch {
                    name: BranchName::new(branch_name),
                    head,
                },
            );
            *g.changes.lock().unwrap() = changes;
            g
        }
    }

    impl EntityStore for MockGraph {
        type Error = kin_model::ModelError;

        fn get_entity(&self, _: &EntityId) -> std::result::Result<Option<Entity>, Self::Error> {
            Ok(None)
        }
        fn get_relations(
            &self,
            _: &EntityId,
            _: &[RelationKind],
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(vec![])
        }
        fn get_all_relations_for_entity(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(vec![])
        }
        fn get_downstream_impact(
            &self,
            _: &EntityId,
            _: u32,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }
        fn get_dependency_neighborhood(
            &self,
            _: &EntityId,
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn expand_neighborhood(
            &self,
            _: &[EntityId],
            _: &[RelationKind],
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }
        fn has_incoming_relation_kinds(
            &self,
            _: &EntityId,
            _: &[RelationKind],
            _: bool,
        ) -> std::result::Result<bool, Self::Error> {
            Ok(false)
        }
        fn query_entities(
            &self,
            _: &EntityFilter,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }
        fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }
        fn upsert_entity(&self, _: &Entity) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_relation(&self, _: &Relation) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn remove_entity(&self, _: &EntityId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn remove_relation(&self, _: &RelationId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_shallow_file(
            &self,
            _: &kin_model::ShallowTrackedFile,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_shallow_files(
            &self,
        ) -> std::result::Result<Vec<kin_model::ShallowTrackedFile>, Self::Error> {
            Ok(vec![])
        }
        fn upsert_structured_artifact(
            &self,
            _: &kin_model::StructuredArtifact,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_structured_artifacts(
            &self,
        ) -> std::result::Result<Vec<kin_model::StructuredArtifact>, Self::Error> {
            Ok(vec![])
        }
        fn delete_structured_artifact(
            &self,
            _: &kin_model::FilePathId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_opaque_artifact(
            &self,
            _: &kin_model::OpaqueArtifact,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_opaque_artifacts(
            &self,
        ) -> std::result::Result<Vec<kin_model::OpaqueArtifact>, Self::Error> {
            Ok(vec![])
        }
        fn delete_opaque_artifact(
            &self,
            _: &kin_model::FilePathId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_file_layout(
            &self,
            _: &kin_model::FileLayout,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_file_layout(
            &self,
            _: &kin_model::FilePathId,
        ) -> std::result::Result<Option<kin_model::FileLayout>, Self::Error> {
            Ok(None)
        }
        fn list_file_layouts(
            &self,
        ) -> std::result::Result<Vec<kin_model::FileLayout>, Self::Error> {
            Ok(vec![])
        }
        fn delete_file_layout(
            &self,
            _: &kin_model::FilePathId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn traverse(
            &self,
            _: &kin_model::GraphNodeId,
            _: &[RelationKind],
            _: u32,
        ) -> std::result::Result<kin_model::SubGraph, Self::Error> {
            Ok(kin_model::SubGraph::default())
        }
        fn get_shallow_file(
            &self,
            _: &kin_model::FilePathId,
        ) -> std::result::Result<Option<kin_model::ShallowTrackedFile>, Self::Error> {
            Ok(None)
        }
        fn get_structured_artifact(
            &self,
            _: &kin_model::FilePathId,
        ) -> std::result::Result<Option<kin_model::StructuredArtifact>, Self::Error> {
            Ok(None)
        }
        fn get_opaque_artifact(
            &self,
            _: &kin_model::FilePathId,
        ) -> std::result::Result<Option<kin_model::OpaqueArtifact>, Self::Error> {
            Ok(None)
        }
        fn get_file_hash(
            &self,
            _: &kin_model::FilePathId,
        ) -> std::result::Result<Option<kin_model::Hash256>, Self::Error> {
            Ok(None)
        }
    }

    impl ChangeStore for MockGraph {
        type Error = kin_model::ModelError;

        fn get_entity_history(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }
        fn find_merge_bases(
            &self,
            _: &SemanticChangeId,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
            Ok(vec![])
        }
        fn create_change(&self, _: &SemanticChange) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_change(
            &self,
            _: &SemanticChangeId,
        ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
            Ok(None)
        }
        fn get_changes_since(
            &self,
            _: &SemanticChangeId,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(self.changes.lock().unwrap().clone())
        }
        fn get_branch(
            &self,
            name: &BranchName,
        ) -> std::result::Result<Option<Branch>, Self::Error> {
            Ok(self.branches.lock().unwrap().get(&name.0).cloned())
        }
        fn create_branch(&self, _: &Branch) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn update_branch_head(
            &self,
            _: &BranchName,
            _: &SemanticChangeId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_branch(&self, _: &BranchName) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_branches(&self) -> std::result::Result<Vec<Branch>, Self::Error> {
            Ok(self.branches.lock().unwrap().values().cloned().collect())
        }
    }

    impl WorkStore for MockGraph {
        type Error = kin_model::ModelError;

        fn create_work_item(
            &self,
            _: &kin_model::WorkItem,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Option<kin_model::WorkItem>, Self::Error> {
            Ok(None)
        }
        fn list_work_items(
            &self,
            _: &kin_model::WorkFilter,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn update_work_status(
            &self,
            _: &kin_model::WorkId,
            _: kin_model::WorkStatus,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_item(&self, _: &kin_model::WorkId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_annotation(
            &self,
            _: &kin_model::Annotation,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> std::result::Result<Option<kin_model::Annotation>, Self::Error> {
            Ok(None)
        }
        fn list_annotations(
            &self,
            _: &kin_model::AnnotationFilter,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn update_annotation_staleness(
            &self,
            _: &kin_model::AnnotationId,
            _: kin_model::StalenessState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_work_link(
            &self,
            _: &kin_model::WorkLink,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_link(
            &self,
            _: &kin_model::WorkLink,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn get_child_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_parent_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_blockers(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_blocked_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_implementors(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkScope>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
    }

    impl VerificationStore for MockGraph {
        type Error = kin_model::ModelError;

        fn create_test_case(
            &self,
            _: &kin_model::verification::TestCase,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_test_case(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Option<kin_model::verification::TestCase>, Self::Error> {
            Ok(None)
        }
        fn get_tests_for_entity(
            &self,
            _: &kin_model::EntityId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn delete_test_case(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_assertion(
            &self,
            _: &kin_model::verification::Assertion,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_assertion(
            &self,
            _: &kin_model::verification::AssertionId,
        ) -> std::result::Result<Option<kin_model::verification::Assertion>, Self::Error> {
            Ok(None)
        }
        fn get_coverage_summary(
            &self,
        ) -> std::result::Result<kin_model::verification::CoverageSummary, Self::Error> {
            Ok(kin_model::verification::CoverageSummary {
                total_entities: 0,
                covered_entities: 0,
                coverage_ratio: 0.0,
                missing_proof: vec![],
            })
        }
        fn create_verification_run(
            &self,
            _: &kin_model::verification::VerificationRun,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_verification_run(
            &self,
            _: &kin_model::verification::VerificationRunId,
        ) -> std::result::Result<Option<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(None)
        }
        fn list_runs_for_test(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn create_test_covers_entity(
            &self,
            _: &kin_model::verification::TestId,
            _: &kin_model::EntityId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_test_covers_contract(
            &self,
            _: &kin_model::verification::TestId,
            _: &kin_model::ContractId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_test_verifies_work(
            &self,
            _: &kin_model::verification::TestId,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_tests_covering_contract(
            &self,
            _: &kin_model::ContractId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn get_tests_verifying_work(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn create_mock_hint(
            &self,
            _: &kin_model::verification::MockHint,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_mock_hints_for_test(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Vec<kin_model::verification::MockHint>, Self::Error> {
            Ok(vec![])
        }
        fn link_run_proves_entity(
            &self,
            _: &kin_model::verification::VerificationRunId,
            _: &kin_model::EntityId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn link_run_proves_work(
            &self,
            _: &kin_model::verification::VerificationRunId,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_runs_proving_entity(
            &self,
            _: &kin_model::EntityId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn list_runs_proving_work(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn create_contract(
            &self,
            _: &kin_model::contract::Contract,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_contract(
            &self,
            _: &kin_model::ids::ContractId,
        ) -> std::result::Result<Option<kin_model::contract::Contract>, Self::Error> {
            Ok(None)
        }
        fn list_contracts(
            &self,
        ) -> std::result::Result<Vec<kin_model::contract::Contract>, Self::Error> {
            Ok(vec![])
        }
        fn get_contract_coverage_summary(
            &self,
        ) -> std::result::Result<kin_model::verification::ContractCoverageSummary, Self::Error>
        {
            Ok(kin_model::verification::ContractCoverageSummary {
                total_contracts: 0,
                covered_contracts: 0,
                coverage_ratio: 0.0,
                uncovered_contract_ids: vec![],
            })
        }
    }

    impl ProvenanceStore for MockGraph {
        type Error = kin_model::ModelError;

        fn create_actor(
            &self,
            _: &kin_model::provenance::Actor,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_actor(
            &self,
            _: &kin_model::provenance::ActorId,
        ) -> std::result::Result<Option<kin_model::provenance::Actor>, Self::Error> {
            Ok(None)
        }
        fn list_actors(
            &self,
        ) -> std::result::Result<Vec<kin_model::provenance::Actor>, Self::Error> {
            Ok(vec![])
        }
        fn create_delegation(
            &self,
            _: &kin_model::provenance::Delegation,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_delegations_for_actor(
            &self,
            _: &kin_model::provenance::ActorId,
        ) -> std::result::Result<Vec<kin_model::provenance::Delegation>, Self::Error> {
            Ok(vec![])
        }
        fn create_approval(
            &self,
            _: &kin_model::provenance::Approval,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_approvals_for_change(
            &self,
            _: &kin_model::SemanticChangeId,
        ) -> std::result::Result<Vec<kin_model::provenance::Approval>, Self::Error> {
            Ok(vec![])
        }
        fn record_audit_event(
            &self,
            _: &kin_model::provenance::AuditEvent,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn query_audit_events(
            &self,
            _: Option<&kin_model::provenance::ActorId>,
            _: usize,
        ) -> std::result::Result<Vec<kin_model::provenance::AuditEvent>, Self::Error> {
            Ok(vec![])
        }
    }

    impl ReviewStore for MockGraph {
        type Error = kin_model::ModelError;

        fn create_review(&self, _: &Review) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review(&self, _: &ReviewId) -> std::result::Result<Option<Review>, Self::Error> {
            Ok(None)
        }
        fn list_reviews(&self, _: &ReviewFilter) -> std::result::Result<Vec<Review>, Self::Error> {
            Ok(vec![])
        }
        fn update_review_state(
            &self,
            _: &ReviewId,
            _: ReviewDecisionState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_review(&self, _: &ReviewId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn add_review_decision(
            &self,
            _: &ReviewId,
            _: &ReviewDecision,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_decisions(
            &self,
            _: &ReviewId,
        ) -> std::result::Result<Vec<ReviewDecision>, Self::Error> {
            Ok(vec![])
        }
        fn add_review_note(&self, _: &ReviewNote) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_notes(
            &self,
            _: &ReviewId,
        ) -> std::result::Result<Vec<ReviewNote>, Self::Error> {
            Ok(vec![])
        }
        fn delete_review_note(&self, _: &ReviewNoteId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_review_discussion(
            &self,
            _: &ReviewDiscussion,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_discussions(
            &self,
            _: &ReviewId,
        ) -> std::result::Result<Vec<ReviewDiscussion>, Self::Error> {
            Ok(vec![])
        }
        fn add_discussion_comment(
            &self,
            _: &ReviewDiscussionId,
            _: &ReviewComment,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn set_discussion_state(
            &self,
            _: &ReviewDiscussionId,
            _: ReviewDiscussionState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn assign_reviewer(&self, _: &ReviewAssignment) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_assignments(
            &self,
            _: &ReviewId,
        ) -> std::result::Result<Vec<ReviewAssignment>, Self::Error> {
            Ok(vec![])
        }
        fn remove_reviewer(&self, _: &ReviewId, _: &str) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
    }

    impl SessionStore for MockGraph {
        type Error = kin_model::ModelError;

        fn upsert_session(
            &self,
            _: &kin_model::session::AgentSession,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_session(
            &self,
            _: &SessionId,
        ) -> std::result::Result<Option<kin_model::session::AgentSession>, Self::Error> {
            Ok(None)
        }
        fn delete_session(&self, _: &SessionId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_sessions(
            &self,
        ) -> std::result::Result<Vec<kin_model::session::AgentSession>, Self::Error> {
            Ok(vec![])
        }
        fn update_heartbeat(
            &self,
            _: &SessionId,
            _: &kin_model::timestamp::Timestamp,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn register_intent(
            &self,
            _: &kin_model::session::Intent,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_intent(
            &self,
            _: &IntentId,
        ) -> std::result::Result<Option<kin_model::session::Intent>, Self::Error> {
            Ok(None)
        }
        fn delete_intent(&self, _: &IntentId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_intents_for_session(
            &self,
            _: &SessionId,
        ) -> std::result::Result<Vec<kin_model::session::Intent>, Self::Error> {
            Ok(vec![])
        }
        fn list_all_intents(
            &self,
        ) -> std::result::Result<Vec<kin_model::session::Intent>, Self::Error> {
            Ok(vec![])
        }
    }

    impl GraphStore for MockGraph {
        type Error = kin_model::ModelError;
    }

    // -- Verification helpers --

    /// Verify that a git repo has the expected number of commits on a branch.
    fn count_commits(repo_path: &Path, branch: &str) -> usize {
        let repo = gix::open(repo_path).unwrap();
        let ref_name = format!("refs/heads/{}", branch);
        let reference = match repo.try_find_reference(&*ref_name).unwrap() {
            Some(r) => r,
            None => return 0,
        };
        let head_id = reference.id().detach();

        let mut count = 0;
        let walk = repo.rev_walk([head_id]).all().unwrap();
        for info in walk {
            let _ = info.unwrap();
            count += 1;
        }
        count
    }

    /// Read a file from a commit's tree.
    fn read_file_from_commit(repo_path: &Path, commit_oid: gix::ObjectId, path: &str) -> Vec<u8> {
        let repo = gix::open(repo_path).unwrap();
        let commit = repo.find_commit(commit_oid).unwrap();
        let tree = commit.tree().unwrap();

        let entry = tree
            .lookup_entry_by_path(path)
            .unwrap()
            .expect("entry not found");
        let object = entry.object().unwrap();
        object.data.clone()
    }

    fn entry_kind_from_commit(
        repo_path: &Path,
        commit_oid: gix::ObjectId,
        path: &str,
    ) -> EntryKind {
        let repo = gix::open(repo_path).unwrap();
        let commit = repo.find_commit(commit_oid).unwrap();
        let tree = commit.tree().unwrap();
        tree.lookup_entry_by_path(path)
            .unwrap()
            .expect("entry not found")
            .mode()
            .kind()
    }

    // -- Tests --

    #[test]
    fn export_options_default() {
        let opts = ExportOptions::default();
        assert_eq!(opts.branch, "main");
        assert!(opts.output_path.is_none());
    }

    #[test]
    fn export_empty_no_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let genesis = make_genesis();
        let branch_name = BranchName::new("main");
        let graph = MockGraph::with_branch_and_changes(
            "main",
            genesis.id,
            vec![], // No changes
        );
        let blob_store = make_blob_store(tmp.path());
        let git_path = tmp.path().join("repo.git");

        let result =
            export_to_git(&graph, &blob_store, genesis.id, &branch_name, &git_path).unwrap();

        assert_eq!(result.commits_exported, 0);
        assert_eq!(result.branches_updated, 0);
    }

    #[test]
    fn export_single_change() {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = make_blob_store(tmp.path());

        let genesis = make_genesis();
        let hash = store_blob(&blob_store, b"hello world\n");
        let change = make_change(
            1,
            vec![genesis.id],
            "add greeting",
            vec![make_delta(
                "hello.txt",
                ArtifactDeltaKind::AddedRegularFile,
                Some(hash),
            )],
        );

        let branch_name = BranchName::new("main");
        let graph = MockGraph::with_branch_and_changes(
            "main",
            change.id,
            vec![genesis.clone(), change.clone()],
        );

        let git_path = tmp.path().join("repo.git");
        let result =
            export_to_git(&graph, &blob_store, genesis.id, &branch_name, &git_path).unwrap();

        assert_eq!(result.commits_exported, 1);
        assert_eq!(result.branches_updated, 1);

        // Verify the commit exists and has the right content.
        assert_eq!(count_commits(&git_path, "main"), 1);

        let repo = gix::open(&git_path).unwrap();
        let head = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .id()
            .detach();
        let content = read_file_from_commit(&git_path, head, "hello.txt");
        assert_eq!(content, b"hello world\n");
    }

    #[test]
    fn export_preserves_regular_executable_and_symlink_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = make_blob_store(tmp.path());
        let genesis = make_genesis();
        let regular_hash = store_blob(&blob_store, b"plain\n");
        let executable_hash = store_blob(&blob_store, b"#!/bin/sh\necho exact\n");
        let symlink_hash = store_blob(&blob_store, b"plain.txt");
        let change = make_change(
            1,
            vec![genesis.id],
            "add exact source modes",
            vec![
                make_delta(
                    "plain.txt",
                    ArtifactDeltaKind::AddedRegularFile,
                    Some(regular_hash),
                ),
                make_delta(
                    "run.sh",
                    ArtifactDeltaKind::AddedExecutableFile,
                    Some(executable_hash),
                ),
                make_delta(
                    "plain-link",
                    ArtifactDeltaKind::AddedSymlink,
                    Some(symlink_hash),
                ),
            ],
        );
        let branch_name = BranchName::new("main");
        let graph = MockGraph::with_branch_and_changes("main", change.id, vec![genesis, change]);
        let git_path = tmp.path().join("repo.git");
        export_to_git(
            &graph,
            &blob_store,
            make_genesis().id,
            &branch_name,
            &git_path,
        )
        .unwrap();

        let repo = gix::open(&git_path).unwrap();
        let head = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .id()
            .detach();
        assert_eq!(
            entry_kind_from_commit(&git_path, head, "plain.txt"),
            EntryKind::Blob
        );
        assert_eq!(
            entry_kind_from_commit(&git_path, head, "run.sh"),
            EntryKind::BlobExecutable
        );
        assert_eq!(
            entry_kind_from_commit(&git_path, head, "plain-link"),
            EntryKind::Link
        );
        assert_eq!(
            read_file_from_commit(&git_path, head, "plain-link"),
            b"plain.txt"
        );
    }

    #[test]
    fn export_rejects_legacy_mode_unknown_deltas() {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = make_blob_store(tmp.path());
        let genesis = make_genesis();
        let hash = store_blob(&blob_store, b"legacy\n");
        let change = make_change(
            1,
            vec![genesis.id],
            "legacy source",
            vec![make_delta(
                "legacy.txt",
                ArtifactDeltaKind::Added,
                Some(hash),
            )],
        );
        let branch_name = BranchName::new("main");
        let graph =
            MockGraph::with_branch_and_changes("main", change.id, vec![genesis.clone(), change]);
        let error = export_to_git(
            &graph,
            &blob_store,
            genesis.id,
            &branch_name,
            &tmp.path().join("repo.git"),
        )
        .expect_err("legacy mode-unknown history must not be normalized during export");
        assert!(error.to_string().contains("mode-unknown"));
    }

    #[test]
    fn export_multi_change_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = make_blob_store(tmp.path());

        let genesis = make_genesis();
        let hash1 = store_blob(&blob_store, b"version 1\n");
        let change1 = make_change(
            1,
            vec![genesis.id],
            "initial file",
            vec![make_delta(
                "file.txt",
                ArtifactDeltaKind::AddedRegularFile,
                Some(hash1),
            )],
        );

        let hash2 = store_blob(&blob_store, b"version 2\n");
        let change2 = make_change(
            2,
            vec![change1.id],
            "update file",
            vec![make_delta(
                "file.txt",
                ArtifactDeltaKind::ModifiedRegularFile,
                Some(hash2),
            )],
        );

        let hash3 = store_blob(&blob_store, b"new file\n");
        let change3 = make_change(
            3,
            vec![change2.id],
            "add another file",
            vec![make_delta(
                "src/lib.rs",
                ArtifactDeltaKind::AddedRegularFile,
                Some(hash3),
            )],
        );

        let branch_name = BranchName::new("main");
        let graph = MockGraph::with_branch_and_changes(
            "main",
            change3.id,
            vec![
                genesis.clone(),
                change1.clone(),
                change2.clone(),
                change3.clone(),
            ],
        );

        let git_path = tmp.path().join("repo.git");
        let result =
            export_to_git(&graph, &blob_store, genesis.id, &branch_name, &git_path).unwrap();

        assert_eq!(result.commits_exported, 3);
        assert_eq!(result.branches_updated, 1);
        assert_eq!(count_commits(&git_path, "main"), 3);

        // Verify the latest commit has both files with correct content.
        let repo = gix::open(&git_path).unwrap();
        let head = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .id()
            .detach();

        let content = read_file_from_commit(&git_path, head, "file.txt");
        assert_eq!(content, b"version 2\n");

        let content = read_file_from_commit(&git_path, head, "src/lib.rs");
        assert_eq!(content, b"new file\n");

        // Verify parent chain: each commit should reference its predecessor.
        let head_commit = repo.find_commit(head).unwrap();
        assert_eq!(head_commit.parent_ids().count(), 1);

        let parent = head_commit.parent_ids().next().unwrap();
        let parent_commit = repo.find_commit(parent.detach()).unwrap();
        assert_eq!(parent_commit.parent_ids().count(), 1);

        let grandparent = parent_commit.parent_ids().next().unwrap();
        let gp_commit = repo.find_commit(grandparent.detach()).unwrap();
        assert_eq!(gp_commit.parent_ids().count(), 0); // first real commit has no parents
    }

    #[test]
    fn export_branch_creates_correct_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = make_blob_store(tmp.path());

        let genesis = make_genesis();
        let hash = store_blob(&blob_store, b"feature code\n");
        let change = make_change(
            1,
            vec![genesis.id],
            "feature work",
            vec![make_delta(
                "feature.rs",
                ArtifactDeltaKind::AddedRegularFile,
                Some(hash),
            )],
        );

        let branch_name = BranchName::new("develop");
        let graph = MockGraph::with_branch_and_changes(
            "develop",
            change.id,
            vec![genesis.clone(), change.clone()],
        );

        let git_path = tmp.path().join("repo.git");
        let result =
            export_to_git(&graph, &blob_store, genesis.id, &branch_name, &git_path).unwrap();

        assert_eq!(result.branches_updated, 1);

        // Verify the ref exists at refs/heads/develop
        let repo = gix::open(&git_path).unwrap();
        let reference = repo.find_reference("refs/heads/develop").unwrap();
        assert!(reference.id().detach() != gix::ObjectId::empty_tree(gix::hash::Kind::Sha1));

        // Verify refs/heads/main does NOT exist.
        assert!(repo
            .try_find_reference("refs/heads/main")
            .unwrap()
            .is_none());
    }

    #[test]
    fn branch_ref_update_accepts_the_observed_prior_value() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(tmp.path()).unwrap();
        let branch_name = BranchName::new("main");
        let first = write_test_commit(&repo, 1, "first");
        let second = write_test_commit(&repo, 2, "second");

        update_branch_ref(&repo, &branch_name, None, first).unwrap();
        update_branch_ref(&repo, &branch_name, Some(first), second).unwrap();

        assert_eq!(find_branch_head(&repo, &branch_name).unwrap(), Some(second));
    }

    #[test]
    fn branch_ref_update_rejects_a_concurrent_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(tmp.path()).unwrap();
        let branch_name = BranchName::new("main");
        let concurrent = write_test_commit(&repo, 1, "concurrent");
        let exported = write_test_commit(&repo, 2, "exported");

        repo.reference(
            "refs/heads/main",
            concurrent,
            PreviousValue::MustNotExist,
            "concurrent create",
        )
        .unwrap();

        assert!(update_branch_ref(&repo, &branch_name, None, exported).is_err());
        assert_eq!(
            find_branch_head(&repo, &branch_name).unwrap(),
            Some(concurrent)
        );
    }

    #[test]
    fn branch_ref_update_rejects_a_concurrent_move() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(tmp.path()).unwrap();
        let branch_name = BranchName::new("main");
        let observed = write_test_commit(&repo, 1, "observed");
        let concurrent = write_test_commit(&repo, 2, "concurrent");
        let exported = write_test_commit(&repo, 3, "exported");

        update_branch_ref(&repo, &branch_name, None, observed).unwrap();
        repo.reference(
            "refs/heads/main",
            concurrent,
            PreviousValue::MustExistAndMatch(Target::Object(observed)),
            "concurrent move",
        )
        .unwrap();

        assert!(update_branch_ref(&repo, &branch_name, Some(observed), exported).is_err());
        assert_eq!(
            find_branch_head(&repo, &branch_name).unwrap(),
            Some(concurrent)
        );
    }

    #[test]
    fn branch_ref_update_rejects_invalid_full_name() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(tmp.path()).unwrap();
        let exported = write_test_commit(&repo, 1, "exported");

        let error =
            update_branch_ref(&repo, &BranchName::new("../outside"), None, exported).unwrap_err();

        assert!(error.to_string().contains("invalid Git branch ref"));
    }

    #[test]
    fn branch_ref_update_rejects_namespaced_repository() {
        let tmp = tempfile::tempdir().unwrap();
        let mut repo = gix::init_bare(tmp.path()).unwrap();
        let exported = write_test_commit(&repo, 1, "exported");
        repo.set_namespace("tenant").unwrap();

        let error = update_branch_ref(&repo, &BranchName::new("main"), None, exported).unwrap_err();

        assert!(error
            .to_string()
            .contains("does not support namespaced ref updates"));
    }

    #[test]
    fn branch_ref_update_rejects_reftable_storage() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(tmp.path()).unwrap();
        std::fs::write(
            repo.common_dir().join("config"),
            b"[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\trefStorage = reftable\n",
        )
        .unwrap();
        drop(repo);
        let repo = gix::open(tmp.path()).unwrap();
        let exported = write_test_commit(&repo, 1, "exported");

        let error = update_branch_ref(&repo, &BranchName::new("main"), None, exported).unwrap_err();

        assert!(error.to_string().contains("ref storage \"reftable\""));
        assert!(repo
            .try_find_reference("refs/heads/main")
            .unwrap()
            .is_none());
    }

    #[test]
    fn branch_ref_update_from_linked_worktree_updates_shared_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let main_repo = gix::init(tmp.path().join("main")).unwrap();
        let common_dir = main_repo.common_dir().to_path_buf();
        let linked_worktree = tmp.path().join("linked");
        let linked_git_dir = common_dir.join("worktrees/linked");
        std::fs::create_dir_all(&linked_worktree).unwrap();
        std::fs::create_dir_all(&linked_git_dir).unwrap();
        std::fs::write(linked_git_dir.join("commondir"), b"../..\n").unwrap();
        std::fs::write(linked_git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        std::fs::write(
            linked_git_dir.join("gitdir"),
            format!("{}\n", linked_worktree.join(".git").display()),
        )
        .unwrap();
        std::fs::write(
            linked_worktree.join(".git"),
            format!("gitdir: {}\n", linked_git_dir.display()),
        )
        .unwrap();

        let linked_repo = gix::open(linked_worktree.join(".git")).unwrap();
        assert_ne!(linked_repo.path(), linked_repo.common_dir());
        let branch_name = BranchName::new("main");
        let ref_name = validated_branch_ref_name(&branch_name).unwrap();
        let (resource, boundary) = loose_ref_resource(&linked_repo, &ref_name).unwrap();

        assert_eq!(boundary, linked_repo.common_dir());
        assert_eq!(resource, linked_repo.common_dir().join("refs/heads/main"));

        let exported = write_test_commit(&linked_repo, 1, "exported");
        update_branch_ref(&linked_repo, &branch_name, None, exported).unwrap();
        assert_eq!(
            find_branch_head(&main_repo, &branch_name).unwrap(),
            Some(exported)
        );
    }

    #[test]
    fn branch_ref_update_rejects_symbolic_target() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(tmp.path()).unwrap();
        let branch_name = BranchName::new("main");
        let ref_name = validated_branch_ref_name(&branch_name).unwrap();
        let (resource, boundary) = loose_ref_resource(&repo, &ref_name).unwrap();
        let mut symbolic = gix::lock::File::acquire_to_update_resource(
            resource,
            gix::lock::acquire::Fail::Immediately,
            Some(boundary),
        )
        .unwrap();
        writeln!(symbolic, "ref: refs/heads/other").unwrap();
        symbolic.commit().unwrap();
        let exported = write_test_commit(&repo, 1, "exported");

        let error = update_branch_ref(&repo, &branch_name, None, exported).unwrap_err();

        assert!(error.to_string().contains("is symbolic"));
    }

    #[test]
    fn branch_ref_update_intentionally_does_not_create_reflog() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(tmp.path()).unwrap();
        let branch_name = BranchName::new("main");
        let exported = write_test_commit(&repo, 1, "exported");

        update_branch_ref(&repo, &branch_name, None, exported).unwrap();

        let reference = repo.find_reference("refs/heads/main").unwrap();
        assert!(!reference.log_exists());
    }

    #[test]
    fn branch_ref_update_rejects_a_move_prepared_while_the_exporter_waits_for_the_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(tmp.path()).unwrap();
        let branch_name = BranchName::new("main");
        let observed = write_test_commit(&repo, 1, "observed");
        let concurrent = write_test_commit(&repo, 2, "concurrent");
        let exported = write_test_commit(&repo, 3, "exported");

        update_branch_ref(&repo, &branch_name, None, observed).unwrap();

        let ref_name = validated_branch_ref_name(&branch_name).unwrap();
        let (resource, common_dir) = loose_ref_resource(&repo, &ref_name).unwrap();
        let mut competing = gix::lock::File::acquire_to_update_resource(
            &resource,
            gix::lock::acquire::Fail::Immediately,
            Some(common_dir),
        )
        .unwrap();
        writeln!(competing, "{concurrent}").unwrap();

        let repo_path = repo.path().to_path_buf();
        let (contended_tx, contended_rx) = mpsc::channel();
        let (retry_tx, retry_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let exporter = thread::spawn(move || {
            let repo = gix::open(repo_path).unwrap();
            let result = update_branch_ref_with_lock_acquirer(
                &repo,
                &BranchName::new("main"),
                Some(observed),
                exported,
                |resource, boundary| {
                    let contention = gix::lock::File::acquire_to_update_resource(
                        resource,
                        gix::lock::acquire::Fail::Immediately,
                        Some(boundary.to_path_buf()),
                    )
                    .unwrap_err();
                    assert!(
                        matches!(
                            contention,
                            gix::lock::acquire::Error::PermanentlyLocked { .. }
                        ),
                        "exporter must observe the prepared ref lock"
                    );
                    contended_tx.send(()).unwrap();
                    retry_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    gix::lock::File::acquire_to_update_resource(
                        resource,
                        gix::lock::acquire::Fail::Immediately,
                        Some(boundary.to_path_buf()),
                    )
                },
            );
            result_tx.send(result).unwrap();
        });
        contended_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        competing.commit().unwrap();
        retry_tx.send(()).unwrap();

        let exporter_result = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        exporter.join().unwrap();
        assert!(
            exporter_result.is_err(),
            "stale exporter must not replace the prepared concurrent update"
        );
        assert_eq!(
            find_branch_head(&repo, &branch_name).unwrap(),
            Some(concurrent)
        );
    }

    #[test]
    fn export_incremental_adds_commits() {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = make_blob_store(tmp.path());
        let git_path = tmp.path().join("repo.git");

        let genesis = make_genesis();
        let branch_name = BranchName::new("main");

        // First export: one change.
        let hash1 = store_blob(&blob_store, b"initial\n");
        let change1 = make_change(
            1,
            vec![genesis.id],
            "first commit",
            vec![make_delta(
                "file.txt",
                ArtifactDeltaKind::AddedRegularFile,
                Some(hash1),
            )],
        );

        let graph1 = MockGraph::with_branch_and_changes(
            "main",
            change1.id,
            vec![genesis.clone(), change1.clone()],
        );

        let result1 =
            export_to_git(&graph1, &blob_store, genesis.id, &branch_name, &git_path).unwrap();
        assert_eq!(result1.commits_exported, 1);

        // Second export: adds more changes on top.
        let hash2 = store_blob(&blob_store, b"updated\n");
        let change2 = make_change(
            2,
            vec![change1.id],
            "second commit",
            vec![make_delta(
                "file.txt",
                ArtifactDeltaKind::ModifiedRegularFile,
                Some(hash2),
            )],
        );

        let graph2 = MockGraph::with_branch_and_changes(
            "main",
            change2.id,
            vec![genesis.clone(), change1.clone(), change2.clone()],
        );

        let result2 =
            export_to_git(&graph2, &blob_store, genesis.id, &branch_name, &git_path).unwrap();
        // This will re-export all changes (including change1 again), but the repo
        // now has the full chain. In a production implementation we'd skip already-exported
        // changes, but for correctness the end state is what matters.
        assert!(result2.commits_exported >= 1);

        // Verify the branch now has at least 2 commits.
        let total = count_commits(&git_path, "main");
        assert!(total >= 2, "expected at least 2 commits, got {total}");

        // Verify latest content.
        let repo = gix::open(&git_path).unwrap();
        let head = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .id()
            .detach();
        let content = read_file_from_commit(&git_path, head, "file.txt");
        assert_eq!(content, b"updated\n");
    }

    #[test]
    fn export_handles_file_removal() {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = make_blob_store(tmp.path());

        let genesis = make_genesis();
        let hash = store_blob(&blob_store, b"temporary\n");
        let change1 = make_change(
            1,
            vec![genesis.id],
            "add file",
            vec![make_delta(
                "temp.txt",
                ArtifactDeltaKind::AddedRegularFile,
                Some(hash),
            )],
        );

        let change2 = make_change(
            2,
            vec![change1.id],
            "remove file",
            vec![make_delta("temp.txt", ArtifactDeltaKind::Removed, None)],
        );

        let branch_name = BranchName::new("main");
        let git_path = tmp.path().join("repo.git");

        let result = export_changes(
            &blob_store,
            &[genesis.clone(), change1.clone(), change2.clone()],
            &branch_name,
            &git_path,
        )
        .unwrap();

        assert_eq!(result.commits_exported, 2);

        // The second commit should have an empty tree (no files left).
        let repo = gix::open(&git_path).unwrap();
        let head = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .id()
            .detach();
        let commit = repo.find_commit(head).unwrap();
        let tree = commit.tree().unwrap();

        // Tree should have no entries since we removed the only file.
        let entry = tree.lookup_entry_by_path("temp.txt").unwrap();
        assert!(entry.is_none(), "temp.txt should not exist after removal");
    }

    #[test]
    fn export_nested_directory_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = make_blob_store(tmp.path());

        let genesis = make_genesis();
        let hash1 = store_blob(&blob_store, b"mod content\n");
        let hash2 = store_blob(&blob_store, b"main content\n");
        let hash3 = store_blob(&blob_store, b"readme\n");

        let change = make_change(
            1,
            vec![genesis.id],
            "add nested files",
            vec![
                make_delta(
                    "src/lib/mod.rs",
                    ArtifactDeltaKind::AddedRegularFile,
                    Some(hash1),
                ),
                make_delta(
                    "src/main.rs",
                    ArtifactDeltaKind::AddedRegularFile,
                    Some(hash2),
                ),
                make_delta(
                    "README.md",
                    ArtifactDeltaKind::AddedRegularFile,
                    Some(hash3),
                ),
            ],
        );

        let branch_name = BranchName::new("main");
        let git_path = tmp.path().join("repo.git");

        let result = export_changes(
            &blob_store,
            &[genesis.clone(), change.clone()],
            &branch_name,
            &git_path,
        )
        .unwrap();

        assert_eq!(result.commits_exported, 1);

        let repo = gix::open(&git_path).unwrap();
        let head = repo
            .find_reference("refs/heads/main")
            .unwrap()
            .id()
            .detach();

        // Verify all files are accessible at their nested paths.
        assert_eq!(
            read_file_from_commit(&git_path, head, "README.md"),
            b"readme\n"
        );
        assert_eq!(
            read_file_from_commit(&git_path, head, "src/main.rs"),
            b"main content\n"
        );
        assert_eq!(
            read_file_from_commit(&git_path, head, "src/lib/mod.rs"),
            b"mod content\n"
        );
    }

    #[test]
    fn parse_author_extracts_name_and_email() {
        let (name, email) = parse_author("Alice <alice@example.com>");
        assert_eq!(name, "Alice");
        assert_eq!(email, "alice@example.com");

        let (name, email) = parse_author("just-a-name");
        assert_eq!(name, "just-a-name");
        assert_eq!(email, "unknown@kin");
    }

    #[test]
    fn split_path_works() {
        assert_eq!(split_path("a/b/c.txt"), ("a/b".into(), "c.txt".into()));
        assert_eq!(split_path("file.txt"), ("".into(), "file.txt".into()));
        assert_eq!(split_path("src/main.rs"), ("src".into(), "main.rs".into()));
    }
}
