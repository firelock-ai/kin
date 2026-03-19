use std::path::Path;

use chrono::TimeZone;
use kin_blobs::BlobStore;
use kin_model::{
    ArtifactDelta, ArtifactDeltaKind, AuthorId, BranchName, FilePathId, Hash256, SemanticChange,
    SemanticChangeId, Timestamp,
};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::error::{GitError, Result};

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
    let repo = gix::open(repo_path).map_err(|e| GitError::Git(e.to_string()))?;

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

/// Shallow import: create a single SemanticChange from HEAD's tree.
fn import_shallow(
    repo: &gix::Repository,
    head_id: gix::ObjectId,
    genesis_id: SemanticChangeId,
    blob_store: Option<&BlobStore>,
) -> Result<Vec<ImportedChange>> {
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
    let mut changes = Vec::new();

    // Walk commits in topological order (parents before children).
    let walk = repo
        .rev_walk([head_id])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(|e| GitError::Git(e.to_string()))?;

    for info_result in walk {
        let info = info_result.map_err(|e| GitError::Git(e.to_string()))?;
        let commit = info
            .id()
            .object()
            .map_err(|e| GitError::Git(e.to_string()))?
            .into_commit();

        let is_root = commit.parent_ids().count() == 0;
        let change = commit_to_change(repo, &commit, genesis_id, is_root, blob_store)?;
        let oid_str = info.id.to_string();

        debug!(git_oid = %oid_str, kin_id = %change.id, parents = change.parents.len(), "imported commit");

        changes.push(ImportedChange {
            change,
            git_oid: oid_str,
        });

        if max_commits > 0 && changes.len() >= max_commits {
            info!(count = changes.len(), "reached max_commits limit");
            break;
        }
    }

    // Reverse so oldest commit is first (topological order).
    changes.reverse();

    info!(count = changes.len(), "full history import complete");
    Ok(changes)
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
    let tree = commit.tree().map_err(|e| GitError::Git(e.to_string()))?;
    let mut deltas = Vec::new();

    // For simplicity in this initial implementation, we record all files in the
    // tree as artifacts. A more complete implementation would diff against
    // parent trees to determine Added/Modified/Removed status.
    let recorder = tree
        .traverse()
        .breadthfirst
        .files()
        .map_err(|e| GitError::Git(e.to_string()))?;

    for entry in recorder {
        if !entry.mode.is_blob() {
            continue;
        }

        let path = entry.filepath.to_string();
        let file_id = FilePathId::new(path);
        let mut blob = repo
            .find_blob(entry.oid)
            .map_err(|e| GitError::Git(e.to_string()))?;
        let content = blob.take_data();
        let content_hash = Hash256::from_bytes(kin_blobs::Hash256::digest(&content).0);
        if let Some(store) = blob_store {
            store.write(&content)?;
        }

        let parent_count = commit.parent_ids().count();
        let kind = if parent_count == 0 {
            ArtifactDeltaKind::Added
        } else {
            // Without parent tree diffing, we conservatively mark as Modified.
            // The indexing pipeline will refine this.
            ArtifactDeltaKind::Modified
        };

        deltas.push(ArtifactDelta {
            file_id,
            kind,
            old_hash: None, // Would come from parent tree diff for non-Added kinds
            new_hash: Some(content_hash),
        });
    }

    Ok(deltas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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
}
