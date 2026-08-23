// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact Git projection for repository-v6 authority.
//!
//! Imported Git objects are copied byte-for-byte from graph-owned source CAS.
//! Native Kin changes are projected deterministically on top of those objects
//! from exact `TreeDelta` history. No checkout or raw filesystem file is ever
//! consulted as repository authority.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use gix::objs::tree::{Entry, EntryKind, EntryMode};
use gix::objs::{Commit, Write as _};
use kin_model::{
    validate_semantic_change_id, ChangeOrigin, ExternalChangeAlias, ExternalObjectId,
    ExternalObjectKind, GitExternalAuthority, GitObjectBodyLoader, GitObjectFormat, GitObjectId,
    GitRawTarget, Hash256, RefTarget, RepositoryId, RepositoryRef, RepositoryRefState,
    ResolvedTree, SemanticChange, SemanticChangeId, TreeEntry, WorkspaceHead,
};

use crate::admission_history::admit_semantic_git_import;
use crate::error::{GitError, Result};
use crate::lossless::{
    capture_lossless_git_repository, claim_staging_path, head_edit, publish_staging, ref_edit,
    reject_existing_destination, require_anchored_publication_platform,
    GitObjectFormat as LosslessObjectFormat, LosslessGitRepository,
};
use crate::semantic_import::{plan_semantic_git_import, HistoricalSemanticBinding};

/// Complete graph-owned input needed to project one Kin repository to Git.
#[derive(Debug, Clone)]
pub struct RepositoryGitExportPlan {
    pub repository_id: RepositoryId,
    pub changes: Vec<SemanticChange>,
    pub aliases: Vec<ExternalChangeAlias>,
    pub refs: RepositoryRefState,
    pub head: WorkspaceHead,
    pub git_authority: Option<GitExternalAuthority>,
}

/// Result of capability-anchored publication of a repository-v6 Git projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryGitExportResult {
    pub git_repo_path: PathBuf,
    pub imported_commits_reused: usize,
    pub native_commits_written: usize,
    pub refs_written: usize,
    /// Deterministic semantic-change to Git-commit projection bindings.
    ///
    /// Callers must persist native bindings before accepting a later Git
    /// re-import as the same semantic history. A commit's `kin-change-id`
    /// header is only a hint; it is never sufficient admission authority.
    pub change_commits: Vec<RepositoryGitCommitBinding>,
    /// Exact reachable objects, refs, and HEAD recaptured from the staged
    /// repository before publication.
    pub proof: RepositoryGitExportProof,
}

/// Exact semantic proof for one repository-v6 Git export.
///
/// The proof deliberately excludes local Git config and index bytes. Callers
/// may finish those ordinary-worktree surfaces after export, then bind the
/// complete staged directory through `kin-core` before authority handoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryGitExportProof {
    expected: LosslessGitRepository,
}

/// One exact commit identity produced or reused by repository export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RepositoryGitCommitBinding {
    pub change_id: SemanticChangeId,
    pub commit_oid: GitObjectId,
    pub imported: bool,
}

/// Project repository-v6 authority into a new bare Git repository.
///
/// The destination must not exist. The complete repository is built in an
/// owner-private sibling directory, recaptured through the exact Git ingestion
/// boundary, and published with a retained output-parent capability only after
/// refs and `HEAD` match. Platforms without that namespace primitive fail
/// before creating the export.
pub fn export_repository_to_git<L>(
    plan: &RepositoryGitExportPlan,
    source: &mut L,
    output_path: &Path,
) -> Result<RepositoryGitExportResult>
where
    L: GitObjectBodyLoader,
{
    reject_existing_destination(output_path)?;
    validate_plan_shape(plan)?;
    let object_format = plan
        .git_authority
        .as_ref()
        .map_or(GitObjectFormat::Sha1, |authority| authority.object_format);
    if object_format != GitObjectFormat::Sha1 {
        return Err(GitError::UnsupportedObjectFormat(object_format.to_string()));
    }

    let parent = output_path.parent().ok_or_else(|| {
        GitError::InvalidSnapshot(format!(
            "Git export destination {} has no parent",
            output_path.display()
        ))
    })?;
    require_anchored_publication_platform(output_path)?;
    let mut staging = claim_staging_path(parent)?;
    let result = match build_staging_projection(plan, source, staging.path()) {
        Ok(result) => result,
        Err(error) => return Err(staging.cleanup_after_error(error)),
    };
    if let Err(error) = publish_staging(&mut staging, output_path) {
        return Err(staging.cleanup_after_error(error));
    }

    let (imported_commits_reused, native_commits_written, refs_written, change_commits, proof) =
        result;
    Ok(RepositoryGitExportResult {
        git_repo_path: output_path.to_path_buf(),
        imported_commits_reused,
        native_commits_written,
        refs_written,
        change_commits,
        proof,
    })
}

/// Recapture `repo_path` and require exact semantic equality with a prior
/// repository-v6 export proof.
///
/// Object bodies are verified into an isolated sibling CAS. The repository is
/// read twice by the lossless capture boundary, so ref or object drift during
/// verification fails closed.
pub fn verify_repository_git_export(
    repo_path: &Path,
    proof: &RepositoryGitExportProof,
    expected_tree: &ResolvedTree,
) -> Result<()> {
    reject_external_staged_git_object_sources(repo_path)?;
    let repository_parent = repo_path.parent().ok_or_else(|| {
        GitError::InvalidSnapshot(format!(
            "Git proof target {} has no parent",
            repo_path.display()
        ))
    })?;
    let proof_parent = if repo_path.file_name() == Some(std::ffi::OsStr::new(".git")) {
        repository_parent.parent().ok_or_else(|| {
            GitError::InvalidSnapshot(format!(
                "Git proof target {} has no external proof directory parent",
                repo_path.display()
            ))
        })?
    } else {
        repository_parent
    };
    let proof_directory = tempfile::Builder::new()
        .prefix(".kin-export-reverify.")
        .tempdir_in(proof_parent)
        .map_err(|error| GitError::io(proof_parent, error))?;
    let proof_store = kin_blobs::BlobStore::new(proof_directory.path().to_path_buf())?;
    let actual = capture_lossless_git_repository(
        repo_path,
        proof.expected.repository_id.clone(),
        &proof_store,
    )?;
    reject_external_staged_git_object_sources(repo_path)?;
    if actual != proof.expected {
        return Err(GitError::InvalidSnapshot(
            "staged Git repository no longer matches its exact repository-v6 export proof"
                .to_string(),
        ));
    }
    let semantic = crate::semantic_import::plan_semantic_git_import(&actual, &proof_store)?;
    let actual_tree = &semantic.workspace_seed.base_tree;
    if actual_tree.len() != expected_tree.len()
        || actual_tree
            .artifacts_by_path()
            .zip(expected_tree.artifacts_by_path())
            .any(|(actual, expected)| {
                actual.path != expected.path || actual.entry != expected.entry
            })
    {
        return Err(GitError::InvalidSnapshot(
            "staged Git repository HEAD tree does not match the graph-owned projection tree"
                .to_string(),
        ));
    }
    Ok(())
}

fn reject_external_staged_git_object_sources(repo_path: &Path) -> Result<()> {
    for relative in [
        "objects/info/alternates",
        "objects/info/http-alternates",
        "commondir",
        "gitdir",
    ] {
        let path = repo_path.join(relative);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(GitError::io(&path, error)),
            Ok(_) => {
                return Err(GitError::InvalidSnapshot(format!(
                    "staged Git repository uses external repository/object indirection at {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn build_staging_projection<L>(
    plan: &RepositoryGitExportPlan,
    source: &mut L,
    staging: &Path,
) -> Result<(
    usize,
    usize,
    usize,
    Vec<RepositoryGitCommitBinding>,
    RepositoryGitExportProof,
)>
where
    L: GitObjectBodyLoader,
{
    let mut source = CachedSource::new(source);
    if let Some(authority) = &plan.git_authority {
        authority
            .validate_with_body_loader(&mut source)
            .map_err(|error| {
                GitError::InvalidSnapshot(format!(
                    "stored Git authority failed source-CAS validation: {error}"
                ))
            })?;
    }

    let repo = gix::init_bare(staging)
        .map_err(|error| GitError::Git(format!("initialize {}: {error}", staging.display())))?;
    if let Some(authority) = &plan.git_authority {
        prove_imported_semantics(plan, authority, &mut source, staging)?;
        write_imported_objects(&repo, authority, &mut source)?;
    }

    let ordered = topological_changes(&plan.changes)?;
    let imported = imported_commit_map(plan)?;
    let mut remaining_uses = parent_use_counts(&plan.changes);
    let mut tree_states = BTreeMap::<SemanticChangeId, ResolvedTree>::new();
    let mut commit_ids = BTreeMap::<SemanticChangeId, GitObjectId>::new();
    let mut imported_commits_reused = 0;
    let mut native_commits_written = 0;

    let empty_tree = ResolvedTree::default();
    for change in ordered {
        let parent_tree = match change.parents.first() {
            Some(parent) => tree_states.get(parent).ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "first parent {parent} was not projected before change {}",
                    change.id
                ))
            })?,
            None => &empty_tree,
        };
        let tree = parent_tree.apply(&change.tree_deltas).map_err(|error| {
            GitError::InvalidSnapshot(format!(
                "change {} has an invalid exact tree transition: {error}",
                change.id
            ))
        })?;

        let commit_oid = match change.origin {
            ChangeOrigin::GitCommit { oid } => {
                let expected = imported.get(&change.id).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "Git-origin change {} has no exact external alias",
                        change.id
                    ))
                })?;
                if *expected != oid {
                    return Err(GitError::InvalidSnapshot(format!(
                        "Git-origin change {} names {oid}, but its alias names {expected}",
                        change.id
                    )));
                }
                require_commit_object(&repo, oid)?;
                imported_commits_reused += 1;
                oid
            }
            ChangeOrigin::Native => {
                let tree_id = write_resolved_tree(&repo, &tree, &mut source)?;
                let parents = change
                    .parents
                    .iter()
                    .map(|parent| {
                        commit_ids.get(parent).copied().ok_or_else(|| {
                            GitError::InvalidSnapshot(format!(
                                "parent {parent} has no projected Git commit before change {}",
                                change.id
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let oid = write_native_commit(&repo, change, tree_id, &parents)?;
                native_commits_written += 1;
                oid
            }
        };
        commit_ids.insert(change.id, commit_oid);

        for parent in &change.parents {
            let remaining = remaining_uses.get_mut(parent).ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "change {} has unaccounted parent {parent}",
                    change.id
                ))
            })?;
            *remaining = remaining.checked_sub(1).ok_or_else(|| {
                GitError::InvalidSnapshot(format!("change {} overuses parent {parent}", change.id))
            })?;
            if *remaining == 0 {
                tree_states.remove(parent);
            }
        }
        if remaining_uses.get(&change.id).copied().unwrap_or(0) > 0 {
            tree_states.insert(change.id, tree);
        }
    }

    let projected_refs = project_refs(plan, &commit_ids)?;
    let projected_head = project_head(&plan.head, &commit_ids)?;
    let mut edits = projected_refs
        .refs
        .iter()
        .map(|repository_ref| ref_edit(repository_ref.name.as_bytes(), &repository_ref.target))
        .collect::<Result<Vec<_>>>()?;
    edits.push(head_edit(&projected_head)?);
    repo.edit_references_as(edits, None)
        .map_err(|error| GitError::Git(format!("write projected refs and HEAD: {error}")))?;
    drop(repo);

    let proof = RepositoryGitExportProof {
        expected: prove_staging_projection(plan, &projected_refs, &projected_head, staging)?,
    };
    let origin_by_change = plan
        .changes
        .iter()
        .map(|change| (change.id, change.origin))
        .collect::<BTreeMap<_, _>>();
    let change_commits = commit_ids
        .into_iter()
        .map(|(change_id, commit_oid)| RepositoryGitCommitBinding {
            change_id,
            commit_oid,
            imported: matches!(
                origin_by_change.get(&change_id),
                Some(ChangeOrigin::GitCommit { .. })
            ),
        })
        .collect();
    Ok((
        imported_commits_reused,
        native_commits_written,
        projected_refs.refs.len(),
        change_commits,
        proof,
    ))
}

fn validate_plan_shape(plan: &RepositoryGitExportPlan) -> Result<()> {
    plan.refs.validate()?;
    for repository_ref in &plan.refs.refs {
        if repository_ref.repository_id != plan.repository_id {
            return Err(GitError::InvalidSnapshot(format!(
                "ref {} belongs to {}, not export repository {}",
                repository_ref.name, repository_ref.repository_id, plan.repository_id
            )));
        }
    }
    if let Some(authority) = &plan.git_authority {
        if authority.repository_id != plan.repository_id {
            return Err(GitError::InvalidSnapshot(format!(
                "Git authority belongs to {}, not export repository {}",
                authority.repository_id, plan.repository_id
            )));
        }
        authority.validate_shape().map_err(|error| {
            GitError::InvalidSnapshot(format!("stored Git authority is malformed: {error}"))
        })?;
    }
    let ids = plan
        .changes
        .iter()
        .map(|change| change.id)
        .collect::<HashSet<_>>();
    if ids.len() != plan.changes.len() {
        return Err(GitError::InvalidSnapshot(
            "Git export repeats a semantic change identity".to_string(),
        ));
    }
    for change in &plan.changes {
        validate_semantic_change_id(change)?;
        for parent in &change.parents {
            if !ids.contains(parent) {
                return Err(GitError::InvalidSnapshot(format!(
                    "change {} references missing parent {parent}",
                    change.id
                )));
            }
        }
    }
    Ok(())
}

fn imported_commit_map(
    plan: &RepositoryGitExportPlan,
) -> Result<BTreeMap<SemanticChangeId, GitObjectId>> {
    let mut by_change = BTreeMap::new();
    let mut by_oid = BTreeSet::new();
    for alias in &plan.aliases {
        let change = plan
            .changes
            .iter()
            .find(|change| change.id == alias.change_id)
            .ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "external alias {} references missing change {}",
                    alias.oid, alias.change_id
                ))
            })?;
        alias.validate_change(change)?;
        if alias.repository_id != plan.repository_id {
            return Err(GitError::InvalidSnapshot(format!(
                "external alias {} belongs to {}, not {}",
                alias.oid, alias.repository_id, plan.repository_id
            )));
        }
        if by_change.insert(alias.change_id, alias.oid).is_some() || !by_oid.insert(alias.oid) {
            return Err(GitError::InvalidSnapshot(
                "Git export aliases are not one-to-one".to_string(),
            ));
        }
    }
    let imported_count = plan
        .changes
        .iter()
        .filter(|change| matches!(change.origin, ChangeOrigin::GitCommit { .. }))
        .count();
    if by_change.len() != imported_count {
        return Err(GitError::InvalidSnapshot(format!(
            "Git export has {} aliases for {imported_count} imported changes",
            by_change.len()
        )));
    }
    if imported_count > 0 && plan.git_authority.is_none() {
        return Err(GitError::InvalidSnapshot(
            "Git-origin changes require exact stored Git authority".to_string(),
        ));
    }
    Ok(by_change)
}

fn topological_changes(changes: &[SemanticChange]) -> Result<Vec<&SemanticChange>> {
    let by_id = changes
        .iter()
        .map(|change| (change.id, change))
        .collect::<BTreeMap<_, _>>();
    if by_id.len() != changes.len() {
        return Err(GitError::InvalidSnapshot(
            "Git export repeats a semantic change identity".to_string(),
        ));
    }
    let mut indegree = by_id
        .keys()
        .copied()
        .map(|id| (id, 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut children = BTreeMap::<SemanticChangeId, BTreeSet<SemanticChangeId>>::new();
    for change in changes {
        let unique = change.parents.iter().copied().collect::<BTreeSet<_>>();
        for parent in &unique {
            if !by_id.contains_key(parent) {
                return Err(GitError::InvalidSnapshot(format!(
                    "change {} references missing parent {parent}",
                    change.id
                )));
            }
            children.entry(*parent).or_default().insert(change.id);
        }
        indegree.insert(change.id, unique.len());
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(changes.len());
    while let Some(id) = ready.pop_first() {
        ordered.push(by_id[&id]);
        if let Some(next) = children.get(&id) {
            for child in next {
                let degree = indegree.get_mut(child).expect("known child has indegree");
                *degree = degree.checked_sub(1).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!("change graph indegree underflow at {child}"))
                })?;
                if *degree == 0 {
                    ready.insert(*child);
                }
            }
        }
    }
    if ordered.len() != changes.len() {
        return Err(GitError::InvalidSnapshot(
            "Git export change graph is cyclic".to_string(),
        ));
    }
    Ok(ordered)
}

fn parent_use_counts(changes: &[SemanticChange]) -> BTreeMap<SemanticChangeId, usize> {
    let mut counts = BTreeMap::new();
    for change in changes {
        for parent in &change.parents {
            *counts.entry(*parent).or_default() += 1;
        }
    }
    counts
}

fn write_imported_objects<L>(
    repo: &gix::Repository,
    authority: &GitExternalAuthority,
    source: &mut CachedSource<'_, L>,
) -> Result<()>
where
    L: GitObjectBodyLoader,
{
    for entry in &authority.closure.objects {
        let record = &entry.record;
        let body = source.required(
            &record.body_hash,
            &format!("Git object {}", record.object.oid),
        )?;
        record.validate_raw(&body).map_err(|error| {
            GitError::InvalidSnapshot(format!(
                "Git object {} failed exact body validation: {error}",
                record.object.oid
            ))
        })?;
        let written = repo
            .write_buf(gix_kind(record.object.kind), &body)
            .map_err(|error| {
                GitError::Git(format!(
                    "write imported object {}: {error}",
                    record.object.oid
                ))
            })?;
        if git_object_id(written)? != record.object.oid {
            return Err(GitError::InvalidSnapshot(format!(
                "writing imported object {} produced {written}",
                record.object.oid
            )));
        }
    }
    Ok(())
}

fn prove_imported_semantics<L>(
    plan: &RepositoryGitExportPlan,
    authority: &GitExternalAuthority,
    source: &mut CachedSource<'_, L>,
    staging: &Path,
) -> Result<()>
where
    L: GitObjectBodyLoader,
{
    let proof_path = staging.join(".kin-import-proof-cas");
    let proof_store = kin_blobs::BlobStore::new(proof_path.clone())?;
    for entry in &authority.closure.objects {
        let body = source.required(
            &entry.record.body_hash,
            &format!("Git object {}", entry.record.object.oid),
        )?;
        let written = proof_store.write(&body)?;
        if written.as_bytes() != entry.record.body_hash.as_bytes() {
            return Err(GitError::InvalidSnapshot(format!(
                "Git object {} could not be reproduced in proof CAS",
                entry.record.object.oid
            )));
        }
    }

    let snapshot = lossless_snapshot_from_authority(authority)?;
    let rebuilt = plan_semantic_git_import(&snapshot, &proof_store)?;
    let mut supplied_by_oid = BTreeMap::new();
    for change in plan
        .changes
        .iter()
        .filter(|change| matches!(change.origin, ChangeOrigin::GitCommit { .. }))
    {
        let ChangeOrigin::GitCommit { oid } = change.origin else {
            unreachable!("the filter retains only Git-origin changes");
        };
        if supplied_by_oid.insert(oid, change).is_some() {
            return Err(GitError::InvalidSnapshot(format!(
                "Git export repeats imported commit {oid}"
            )));
        }
    }
    let historical_deltas = rebuilt
        .changes
        .iter()
        .map(|base_change| {
            let ChangeOrigin::GitCommit { oid } = base_change.origin else {
                unreachable!("the exact Git planner only emits Git-origin changes");
            };
            let supplied = supplied_by_oid.get(&oid).ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "Git export omits imported semantic history for commit {oid}"
                ))
            })?;
            Ok(HistoricalSemanticBinding::borrowed(
                base_change.id,
                &supplied.entity_deltas,
                &supplied.relation_deltas,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let rebuilt = rebuilt.with_historical_semantics(&proof_store, historical_deltas)?;
    let rebuilt = admit_semantic_git_import(&rebuilt, &proof_store)?;
    let expected_changes = rebuilt
        .changes
        .into_iter()
        .map(|change| (change.id, change))
        .collect::<BTreeMap<_, _>>();
    let supplied_changes = plan
        .changes
        .iter()
        .filter(|change| matches!(change.origin, ChangeOrigin::GitCommit { .. }))
        .cloned()
        .map(|change| (change.id, change))
        .collect::<BTreeMap<_, _>>();
    let expected_aliases = rebuilt
        .aliases
        .into_iter()
        .map(|alias| (alias.oid, alias))
        .collect::<BTreeMap<_, _>>();
    let supplied_aliases = plan
        .aliases
        .iter()
        .cloned()
        .map(|alias| (alias.oid, alias))
        .collect::<BTreeMap<_, _>>();
    if supplied_changes != expected_changes || supplied_aliases != expected_aliases {
        return Err(GitError::InvalidSnapshot(
            "imported semantic history does not rebuild exactly from stored Git authority"
                .to_string(),
        ));
    }

    drop(proof_store);
    fs::remove_dir_all(&proof_path).map_err(|error| GitError::io(&proof_path, error))?;
    Ok(())
}

fn lossless_snapshot_from_authority(
    authority: &GitExternalAuthority,
) -> Result<LosslessGitRepository> {
    let refs = authority
        .raw_refs
        .iter()
        .map(|raw_ref| {
            Ok(RepositoryRef {
                repository_id: authority.repository_id.clone(),
                name: raw_ref.name.clone(),
                target: ref_target_from_raw(&raw_ref.target),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let (head, default_ref) = match &authority.raw_head {
        GitRawTarget::Direct { object } => (
            WorkspaceHead::Detached {
                target: RefTarget::external_object(*object),
            },
            None,
        ),
        GitRawTarget::Symbolic { target } => (
            WorkspaceHead::Symbolic {
                target: target.clone(),
            },
            Some(target.clone()),
        ),
    };
    let refs = RepositoryRefState { refs, default_ref };
    refs.validate()?;
    Ok(LosslessGitRepository {
        repository_id: authority.repository_id.clone(),
        object_format: match authority.object_format {
            GitObjectFormat::Sha1 => LosslessObjectFormat::Sha1,
            GitObjectFormat::Sha256 => LosslessObjectFormat::Sha256,
        },
        objects: authority
            .closure
            .objects
            .iter()
            .map(|entry| entry.record.clone())
            .collect(),
        refs,
        head,
    })
}

fn ref_target_from_raw(target: &GitRawTarget) -> RefTarget {
    match target {
        GitRawTarget::Direct { object } => RefTarget::external_object(*object),
        GitRawTarget::Symbolic { target } => RefTarget::symbolic(target.clone()),
    }
}

fn require_commit_object(repo: &gix::Repository, oid: GitObjectId) -> Result<()> {
    let object = repo
        .find_object(gix_object_id(oid)?)
        .map_err(|error| GitError::Git(format!("open imported commit {oid}: {error}")))?;
    if object.kind != gix::objs::Kind::Commit {
        return Err(GitError::InvalidSnapshot(format!(
            "imported change alias {oid} does not name a commit"
        )));
    }
    Ok(())
}

#[derive(Debug, Default)]
struct TreeNode {
    children: BTreeMap<Vec<u8>, TreeNodeEntry>,
}

#[derive(Debug)]
enum TreeNodeEntry {
    Directory(TreeNode),
    Leaf { id: gix::ObjectId, kind: EntryKind },
}

fn write_resolved_tree<L>(
    repo: &gix::Repository,
    tree: &ResolvedTree,
    source: &mut CachedSource<'_, L>,
) -> Result<gix::ObjectId>
where
    L: GitObjectBodyLoader,
{
    let mut root = TreeNode::default();
    for artifact in tree.artifacts_by_path() {
        let leaf = materialize_leaf(repo, source, &artifact.path, artifact.entry)?;
        let components = artifact
            .path
            .as_bytes()
            .split(|byte| *byte == b'/')
            .collect::<Vec<_>>();
        insert_components(&mut root, &components, leaf, &artifact.path)?;
    }
    write_tree_node(repo, &root)
}

fn materialize_leaf<L>(
    repo: &gix::Repository,
    source: &mut CachedSource<'_, L>,
    path: &kin_model::RepoPath,
    entry: TreeEntry,
) -> Result<TreeNodeEntry>
where
    L: GitObjectBodyLoader,
{
    let (id, kind) = match entry {
        TreeEntry::Blob { hash, executable } => {
            let body = source.required(&hash, &format!("tree blob {path}"))?;
            let id = repo
                .write_blob(&body)
                .map_err(|error| GitError::Git(format!("write tree blob {path}: {error}")))?
                .detach();
            (
                id,
                if executable {
                    EntryKind::BlobExecutable
                } else {
                    EntryKind::Blob
                },
            )
        }
        TreeEntry::Symlink { target_blob } => {
            let target = source.required(&target_blob, &format!("symlink target {path}"))?;
            (
                repo.write_blob(&target)
                    .map_err(|error| GitError::Git(format!("write symlink {path}: {error}")))?
                    .detach(),
                EntryKind::Link,
            )
        }
        TreeEntry::Gitlink { target } => (gix_object_id(target)?, EntryKind::Commit),
    };
    Ok(TreeNodeEntry::Leaf { id, kind })
}

fn insert_components(
    node: &mut TreeNode,
    components: &[&[u8]],
    leaf: TreeNodeEntry,
    full_path: &kin_model::RepoPath,
) -> Result<()> {
    let (component, remaining) = components
        .split_first()
        .expect("RepoPath always has one component");
    if remaining.is_empty() {
        if node.children.insert(component.to_vec(), leaf).is_some() {
            return Err(GitError::InvalidSnapshot(format!(
                "Git export repeats path {full_path}"
            )));
        }
        return Ok(());
    }
    let child = node
        .children
        .entry(component.to_vec())
        .or_insert_with(|| TreeNodeEntry::Directory(TreeNode::default()));
    match child {
        TreeNodeEntry::Directory(directory) => {
            insert_components(directory, remaining, leaf, full_path)
        }
        TreeNodeEntry::Leaf { .. } => Err(GitError::InvalidSnapshot(format!(
            "Git export path {full_path} collides with a file parent"
        ))),
    }
}

fn write_tree_node(repo: &gix::Repository, node: &TreeNode) -> Result<gix::ObjectId> {
    let mut entries = Vec::with_capacity(node.children.len());
    for (name, child) in &node.children {
        let (oid, kind) = match child {
            TreeNodeEntry::Directory(directory) => {
                (write_tree_node(repo, directory)?, EntryKind::Tree)
            }
            TreeNodeEntry::Leaf { id, kind } => (*id, *kind),
        };
        entries.push(Entry {
            mode: EntryMode::from(kind),
            filename: name.clone().into(),
            oid,
        });
    }
    entries.sort();
    repo.write_object(&gix::objs::Tree { entries })
        .map(|id| id.detach())
        .map_err(|error| GitError::Git(format!("write exact Git tree: {error}")))
}

fn write_native_commit(
    repo: &gix::Repository,
    change: &SemanticChange,
    tree: gix::ObjectId,
    parents: &[GitObjectId],
) -> Result<GitObjectId> {
    let author_name = sanitize_actor(&change.author.0);
    let author = gix::actor::Signature {
        name: author_name.into(),
        email: b"kin@localhost".as_slice().into(),
        time: gix::date::Time::new(change.timestamp.0.timestamp(), 0),
    };
    let parent_ids = parents
        .iter()
        .copied()
        .map(gix_object_id)
        .collect::<Result<Vec<_>>>()?;
    let commit = Commit {
        tree,
        parents: parent_ids.into_iter().collect(),
        author: author.clone(),
        committer: author,
        encoding: None,
        message: change.message.clone().into(),
        extra_headers: vec![(
            b"kin-change-id".as_slice().into(),
            change.id.to_string().into(),
        )],
    };
    let id = repo
        .write_object(&commit)
        .map_err(|error| GitError::Git(format!("write native change {}: {error}", change.id)))?
        .detach();
    git_object_id(id)
}

fn sanitize_actor(value: &str) -> Vec<u8> {
    let mut bytes = value
        .bytes()
        .filter(|byte| !matches!(*byte, b'\n' | b'\r' | b'<' | b'>'))
        .collect::<Vec<_>>();
    if bytes.is_empty() {
        bytes.extend_from_slice(b"Kin");
    }
    bytes
}

fn project_refs(
    plan: &RepositoryGitExportPlan,
    commits: &BTreeMap<SemanticChangeId, GitObjectId>,
) -> Result<RepositoryRefState> {
    let refs = plan
        .refs
        .refs
        .iter()
        .map(|repository_ref| {
            Ok(RepositoryRef {
                repository_id: plan.repository_id.clone(),
                name: repository_ref.name.clone(),
                target: project_target(&repository_ref.target, commits)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let projected = RepositoryRefState {
        refs,
        default_ref: plan.refs.default_ref.clone(),
    };
    projected.validate()?;
    Ok(projected)
}

fn project_head(
    head: &WorkspaceHead,
    commits: &BTreeMap<SemanticChangeId, GitObjectId>,
) -> Result<WorkspaceHead> {
    Ok(match head {
        WorkspaceHead::Symbolic { target } => WorkspaceHead::Symbolic {
            target: target.clone(),
        },
        WorkspaceHead::Detached { target } => WorkspaceHead::Detached {
            target: project_target(target, commits)?,
        },
    })
}

fn project_target(
    target: &RefTarget,
    commits: &BTreeMap<SemanticChangeId, GitObjectId>,
) -> Result<RefTarget> {
    match target {
        RefTarget::Change { change_id } => {
            let oid = commits.get(change_id).copied().ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "ref targets missing semantic change {change_id}"
                ))
            })?;
            Ok(RefTarget::ExternalObject {
                object: ExternalObjectId::new(ExternalObjectKind::Commit, oid),
            })
        }
        RefTarget::ExternalObject { object } => Ok(RefTarget::ExternalObject { object: *object }),
        RefTarget::Symbolic { target } => Ok(RefTarget::Symbolic {
            target: target.clone(),
        }),
    }
}

fn prove_staging_projection(
    plan: &RepositoryGitExportPlan,
    refs: &RepositoryRefState,
    head: &WorkspaceHead,
    staging: &Path,
) -> Result<LosslessGitRepository> {
    let proof_path = staging.join(".kin-export-proof-cas");
    let proof_store = kin_blobs::BlobStore::new(proof_path.clone())?;
    let recaptured =
        capture_lossless_git_repository(staging, plan.repository_id.clone(), &proof_store)?;
    if recaptured.object_format != LosslessObjectFormat::Sha1
        || recaptured.refs != *refs
        || recaptured.head != *head
    {
        return Err(GitError::InvalidSnapshot(
            "staged Git export did not recapture its projected refs and HEAD exactly".to_string(),
        ));
    }
    drop(proof_store);
    fs::remove_dir_all(&proof_path).map_err(|error| GitError::io(&proof_path, error))?;
    Ok(recaptured)
}

fn gix_kind(kind: ExternalObjectKind) -> gix::objs::Kind {
    match kind {
        ExternalObjectKind::Commit => gix::objs::Kind::Commit,
        ExternalObjectKind::Tree => gix::objs::Kind::Tree,
        ExternalObjectKind::Blob => gix::objs::Kind::Blob,
        ExternalObjectKind::Tag => gix::objs::Kind::Tag,
    }
}

fn gix_object_id(oid: GitObjectId) -> Result<gix::ObjectId> {
    gix::ObjectId::from_hex(oid.to_string().as_bytes())
        .map_err(|error| GitError::InvalidSnapshot(format!("invalid Git object ID: {error}")))
}

fn git_object_id(oid: gix::ObjectId) -> Result<GitObjectId> {
    match oid.as_bytes() {
        bytes if bytes.len() == 20 => {
            let mut exact = [0_u8; 20];
            exact.copy_from_slice(bytes);
            Ok(GitObjectId::sha1(exact))
        }
        bytes if bytes.len() == 32 => {
            let mut exact = [0_u8; 32];
            exact.copy_from_slice(bytes);
            Ok(GitObjectId::sha256(exact))
        }
        bytes => Err(GitError::UnsupportedObjectFormat(format!(
            "{}-byte object ID",
            bytes.len()
        ))),
    }
}

struct CachedSource<'a, L> {
    source: &'a mut L,
    bodies: BTreeMap<Hash256, Vec<u8>>,
}

impl<'a, L> CachedSource<'a, L>
where
    L: GitObjectBodyLoader,
{
    fn new(source: &'a mut L) -> Self {
        Self {
            source,
            bodies: BTreeMap::new(),
        }
    }

    fn required(&mut self, hash: &Hash256, context: &str) -> Result<Vec<u8>> {
        let body = self
            .load_body(hash)
            .map_err(|reason| {
                GitError::InvalidSnapshot(format!(
                    "failed to load source body {hash} for {context}: {reason}"
                ))
            })?
            .ok_or_else(|| {
                GitError::InvalidSnapshot(format!("source body {hash} for {context} is absent"))
            })?;
        if kin_blobs::digest_bytes(&body) != *hash.as_bytes() {
            return Err(GitError::InvalidSnapshot(format!(
                "source body {hash} for {context} failed content identity"
            )));
        }
        Ok(body)
    }
}

impl<L> GitObjectBodyLoader for CachedSource<'_, L>
where
    L: GitObjectBodyLoader,
{
    type Error = String;

    fn load_body(
        &mut self,
        body_hash: &Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        if let Some(body) = self.bodies.get(body_hash) {
            return Ok(Some(body.clone()));
        }
        let body = self
            .source
            .load_body(body_hash)
            .map_err(|error| error.to_string())?;
        if let Some(body) = &body {
            self.bodies.insert(*body_hash, body.clone());
        }
        Ok(body)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    use kin_blobs::{BlobError, BlobStore};
    use kin_model::{
        compute_semantic_change_id, ArtifactId, AuthorId, LocatedEntry, RepoPath, ResolvedArtifact,
        Timestamp, TreeDelta,
    };
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;
    use crate::test_support::{fixture_git, FixtureGitCommand};
    use crate::{
        admit_semantic_git_import, build_git_external_authority, plan_semantic_git_import,
    };

    struct StoreLoader<'a> {
        store: &'a BlobStore,
    }

    impl GitObjectBodyLoader for StoreLoader<'_> {
        type Error = String;

        fn load_body(
            &mut self,
            body_hash: &Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            let hash = kin_blobs::Hash256::from_bytes(*body_hash.as_bytes());
            match self.store.read(&hash) {
                Ok(body) => Ok(Some(body)),
                Err(BlobError::NotFound { .. }) => Ok(None),
                Err(error) => Err(error.to_string()),
            }
        }
    }

    #[test]
    fn exports_imported_and_native_mixed_artifacts_from_graph_cas_only() {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        git(&source, &["init", "--initial-branch=main"]);
        git(&source, &["config", "user.email", "kin@example.invalid"]);
        git(&source, &["config", "user.name", "Kin Test"]);

        write_parent(
            &source,
            "compose.yaml",
            b"services:\n  api:\n    image: kin:imported\n",
        );
        write_parent(&source, "Dockerfile", b"FROM scratch\n");
        write_parent(&source, "src/lib.rs", b"pub fn imported() {}\n");
        write_parent(&source, "tools/build.py", b"print('imported')\n");
        write_parent(&source, "scripts/run.sh", b"#!/bin/sh\nexit 0\n");
        write_parent(
            &source,
            "opaque.rs",
            &[0, 255, b'R', b'u', b's', b't', 0, 128],
        );
        write_parent(&source, "assets/payload.bin", &[0, 1, 2, 255, 0, 128]);
        symlink("scripts/run.sh", source.join("run")).unwrap();
        git(&source, &["add", "--all"]);
        add_raw_index_entry(&source, b"fixtures/imported-\xff.bin", &[17, 0, 255, 34]);
        let gitlink_target = GitObjectId::sha1([0x42; 20]);
        let gitlink_oid = "4242424242424242424242424242424242424242";
        git(
            &source,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{gitlink_oid},vendor/dependency"),
            ],
        );
        git(&source, &["commit", "-m", "import exact mixed repository"]);
        let imported_oid = String::from_utf8(git(&source, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_string();

        let store = BlobStore::new(root.path().join("source-cas")).unwrap();
        let repository_id = RepositoryId::new("mixed-export").unwrap();
        let snapshot =
            capture_lossless_git_repository(&source, repository_id.clone(), &store).unwrap();
        let imported = admit_semantic_git_import(
            &plan_semantic_git_import(&snapshot, &store).unwrap(),
            &store,
        )
        .unwrap();
        let authority = build_git_external_authority(&snapshot, &store).unwrap();
        let imported_change = imported.changes.last().unwrap().clone();
        let base_tree = imported
            .commit_trees
            .get(&match imported_change.origin {
                ChangeOrigin::GitCommit { oid } => oid,
                ChangeOrigin::Native => panic!("fixture import produced a native change"),
            })
            .unwrap();
        let gitlink_path = RepoPath::from_utf8("vendor/dependency").unwrap();
        assert_eq!(
            base_tree.artifact_at_path(&gitlink_path).unwrap().entry,
            TreeEntry::gitlink(gitlink_target),
            "semantic import must preserve the exact Gitlink target"
        );

        let compose_path = RepoPath::from_utf8("compose.yaml").unwrap();
        let compose = base_tree.artifact_at_path(&compose_path).unwrap();
        let compose_body =
            b"services:\n  api:\n    image: kin:native\n  worker:\n    image: kin:worker\n";
        let compose_hash = store_body(&store, compose_body);
        let script_path = RepoPath::from_utf8("scripts/run.sh").unwrap();
        let script = base_tree.artifact_at_path(&script_path).unwrap();
        let symlink_path = RepoPath::from_utf8("run").unwrap();
        let existing_symlink = base_tree.artifact_at_path(&symlink_path).unwrap();
        let symlink_hash = store_body(&store, b"compose.yaml");
        let unknown_path = RepoPath::from_utf8("config/policy.unrecognized").unwrap();
        let unknown_hash = store_body(&store, b"arbitrary = true\n");
        let binary_path = RepoPath::from_bytes(b"generated/native-\xff.rs".to_vec()).unwrap();
        let binary_body = [0, 159, 146, 150, 0, 255, b'R', b'S'];
        let binary_hash = store_body(&store, &binary_body);

        let mut native = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![imported_change.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("Kin Native"),
            message: "native exact artifact change".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![
                TreeDelta::Updated {
                    artifact_id: compose.artifact_id,
                    old: LocatedEntry::new(compose.path.clone(), compose.entry),
                    new: LocatedEntry::new(
                        compose_path.clone(),
                        TreeEntry::blob(compose_hash, false),
                    ),
                },
                TreeDelta::Updated {
                    artifact_id: script.artifact_id,
                    old: LocatedEntry::new(script.path.clone(), script.entry),
                    new: LocatedEntry::new(
                        script_path.clone(),
                        match script.entry {
                            TreeEntry::Blob { hash, .. } => TreeEntry::blob(hash, true),
                            other => panic!("fixture script is not a blob: {other:?}"),
                        },
                    ),
                },
                TreeDelta::Updated {
                    artifact_id: existing_symlink.artifact_id,
                    old: LocatedEntry::new(existing_symlink.path.clone(), existing_symlink.entry),
                    new: LocatedEntry::new(symlink_path.clone(), TreeEntry::symlink(symlink_hash)),
                },
                TreeDelta::Added {
                    artifact_id: artifact_id(&unknown_path),
                    new: LocatedEntry::new(
                        unknown_path.clone(),
                        TreeEntry::blob(unknown_hash, false),
                    ),
                },
                TreeDelta::Added {
                    artifact_id: artifact_id(&binary_path),
                    new: LocatedEntry::new(
                        binary_path.clone(),
                        TreeEntry::blob(binary_hash, false),
                    ),
                },
            ],
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        };
        native.id = compute_semantic_change_id(&native).unwrap();
        let expected_tree = base_tree.apply(&native.tree_deltas).unwrap();

        let mut refs = imported.refs.clone();
        let main = refs
            .refs
            .iter_mut()
            .find(|repository_ref| repository_ref.name.as_bytes() == b"refs/heads/main")
            .unwrap();
        main.target = RefTarget::change(native.id);
        let export_plan = RepositoryGitExportPlan {
            repository_id: repository_id.clone(),
            changes: imported
                .changes
                .iter()
                .cloned()
                .chain(std::iter::once(native.clone()))
                .collect(),
            aliases: imported.aliases.clone(),
            refs,
            head: imported.head.clone(),
            git_authority: Some(authority.clone()),
        };
        let exported = root.path().join("export.git");
        let mut loader = StoreLoader { store: &store };
        let result = export_repository_to_git(&export_plan, &mut loader, &exported).unwrap();
        verify_repository_git_export(&exported, &result.proof, &expected_tree).unwrap();
        let wrong_gitlink_tree =
            ResolvedTree::from_artifacts(expected_tree.artifacts().map(|artifact| {
                ResolvedArtifact::new(
                    artifact.artifact_id,
                    artifact.path.clone(),
                    if artifact.path == gitlink_path {
                        TreeEntry::gitlink(GitObjectId::sha1([0x43; 20]))
                    } else {
                        artifact.entry
                    },
                )
            }))
            .unwrap();
        let error = verify_repository_git_export(&exported, &result.proof, &wrong_gitlink_tree)
            .expect_err("the export proof must bind the exact Gitlink commit pointer");
        assert!(
            error.to_string().contains("graph-owned projection tree"),
            "unexpected Gitlink export-proof error: {error}"
        );
        let wrong_tree = ResolvedTree::default();
        let error = verify_repository_git_export(&exported, &result.proof, &wrong_tree)
            .expect_err("the export proof must bind the graph-owned HEAD tree");
        assert!(error.to_string().contains("graph-owned projection tree"));
        assert_eq!(result.imported_commits_reused, 1);
        assert_eq!(result.native_commits_written, 1);
        assert_eq!(result.refs_written, 1);
        assert_eq!(result.change_commits.len(), 2);
        assert_eq!(
            result
                .change_commits
                .iter()
                .filter(|binding| binding.imported)
                .count(),
            1
        );

        git_bare(&exported, &["fsck", "--strict"]);
        assert_eq!(
            String::from_utf8(git_bare(
                &exported,
                &["ls-tree", "main", "--", "vendor/dependency"],
            ))
            .unwrap(),
            format!("160000 commit {gitlink_oid}\tvendor/dependency\n"),
            "repository export must retain the exact Gitlink target"
        );
        assert_eq!(
            String::from_utf8(git_bare(&exported, &["rev-list", "--count", "main"]))
                .unwrap()
                .trim(),
            "2"
        );
        let head_parent = String::from_utf8(git_bare(&exported, &["rev-parse", "main^"])).unwrap();
        assert_eq!(head_parent.trim(), imported_oid);
        assert_eq!(
            git(&source, &["cat-file", "commit", &imported_oid]),
            git_bare(&exported, &["cat-file", "commit", &imported_oid]),
            "the imported raw commit body must remain byte exact"
        );
        let native_commit = git_bare(&exported, &["cat-file", "commit", "main"]);
        let identity_header = format!("kin-change-id {}", native.id);
        assert!(native_commit
            .windows(identity_header.len())
            .any(|window| window == identity_header.as_bytes()));

        let checkout = root.path().join("checkout");
        git_clone_without_checkout(&exported, &checkout);
        git(
            &checkout,
            &[
                "checkout",
                "HEAD",
                "--",
                "compose.yaml",
                "config/policy.unrecognized",
                "opaque.rs",
                "run",
                "scripts/run.sh",
            ],
        );
        assert_eq!(
            fs::read(checkout.join("compose.yaml")).unwrap(),
            compose_body
        );
        assert_eq!(
            fs::read(checkout.join("config/policy.unrecognized")).unwrap(),
            b"arbitrary = true\n"
        );
        assert_eq!(
            tree_blob(&exported, "HEAD", b"generated/native-\xff.rs"),
            binary_body
        );
        assert_eq!(
            tree_blob(&exported, "HEAD", b"fixtures/imported-\xff.bin"),
            [17, 0, 255, 34]
        );
        assert_eq!(
            fs::read(checkout.join("opaque.rs")).unwrap(),
            [0, 255, b'R', b'u', b's', b't', 0, 128]
        );
        assert_eq!(
            fs::read_link(checkout.join("run")).unwrap(),
            Path::new("compose.yaml")
        );
        let script_mode = fs::metadata(checkout.join("scripts/run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(script_mode & 0o111, 0);
        git_bare(
            &exported,
            &["update-ref", "refs/heads/unproved", "refs/heads/main"],
        );
        let error = verify_repository_git_export(&exported, &result.proof, &expected_tree)
            .expect_err("a new ref must invalidate the exact repository export proof");
        assert!(
            error
                .to_string()
                .contains("exact repository-v6 export proof"),
            "unexpected export proof error: {error}"
        );

        let mut tampered_change = imported.changes[0].clone();
        tampered_change.message.push_str(" but not from raw Git");
        tampered_change.id = compute_semantic_change_id(&tampered_change).unwrap();
        let mut tampered_alias = imported.aliases[0].clone();
        tampered_alias.change_id = tampered_change.id;
        let tampered = RepositoryGitExportPlan {
            repository_id,
            changes: vec![tampered_change],
            aliases: vec![tampered_alias],
            refs: imported.refs,
            head: imported.head,
            git_authority: Some(authority),
        };
        let rejected = root.path().join("rejected.git");
        let error = export_repository_to_git(&tampered, &mut loader, &rejected).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not rebuild exactly from stored Git authority"),
            "unexpected error: {error}"
        );
        assert!(
            !rejected.exists(),
            "failed export must not publish a repository"
        );
    }

    #[test]
    fn exports_unborn_repository_without_inventing_history_or_refs() {
        let root = tempdir().unwrap();
        let store = BlobStore::new(root.path().join("source-cas")).unwrap();
        let repository_id = RepositoryId::new("unborn-export").unwrap();
        let main = kin_model::RefName::from_bytes(b"refs/heads/main".to_vec()).unwrap();
        let plan = RepositoryGitExportPlan {
            repository_id,
            changes: Vec::new(),
            aliases: Vec::new(),
            refs: RepositoryRefState {
                refs: Vec::new(),
                default_ref: Some(main.clone()),
            },
            head: WorkspaceHead::Symbolic {
                target: main.clone(),
            },
            git_authority: None,
        };
        let exported = root.path().join("unborn.git");
        let mut loader = StoreLoader { store: &store };
        let result = export_repository_to_git(&plan, &mut loader, &exported).unwrap();
        verify_repository_git_export(&exported, &result.proof, &ResolvedTree::default()).unwrap();
        assert_eq!(result.imported_commits_reused, 0);
        assert_eq!(result.native_commits_written, 0);
        assert_eq!(result.refs_written, 0);
        assert!(result.change_commits.is_empty());
        assert_eq!(
            String::from_utf8(git_bare(&exported, &["symbolic-ref", "HEAD"]))
                .unwrap()
                .trim(),
            "refs/heads/main"
        );
        let show_ref = fixture_git()
            .arg("--git-dir")
            .arg(&exported)
            .arg("show-ref")
            .output()
            .unwrap();
        assert_eq!(show_ref.status.code(), Some(1));
        assert!(show_ref.stdout.is_empty());
    }

    #[test]
    fn native_merge_preserves_parent_order_and_first_parent_tree() {
        let root = tempdir().unwrap();
        let store = BlobStore::new(root.path().join("source-cas")).unwrap();
        let repository_id = RepositoryId::new("native-merge-export").unwrap();
        let path = RepoPath::from_utf8("compose.yaml").unwrap();
        let artifact_id = artifact_id(&path);
        let root_hash = store_body(&store, b"services:\n  api:\n    image: root\n");
        let main_hash = store_body(&store, b"services:\n  api:\n    image: main\n");
        let feature_hash = store_body(&store, b"services:\n  api:\n    image: feature\n");
        let root_entry = TreeEntry::blob(root_hash, false);
        let main_entry = TreeEntry::blob(main_hash, false);
        let feature_entry = TreeEntry::blob(feature_hash, false);

        let root_change = native_change(
            Vec::new(),
            "root",
            vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(path.clone(), root_entry),
            }],
        );
        let main_change = native_change(
            vec![root_change.id],
            "main",
            vec![TreeDelta::Updated {
                artifact_id,
                old: LocatedEntry::new(path.clone(), root_entry),
                new: LocatedEntry::new(path.clone(), main_entry),
            }],
        );
        let feature_change = native_change(
            vec![root_change.id],
            "feature",
            vec![TreeDelta::Updated {
                artifact_id,
                old: LocatedEntry::new(path.clone(), root_entry),
                new: LocatedEntry::new(path.clone(), feature_entry),
            }],
        );
        let merge_change = native_change(
            vec![main_change.id, feature_change.id],
            "merge feature",
            Vec::new(),
        );
        let main = kin_model::RefName::from_bytes(b"refs/heads/main".to_vec()).unwrap();
        let feature = kin_model::RefName::from_bytes(b"refs/heads/feature".to_vec()).unwrap();
        let plan = RepositoryGitExportPlan {
            repository_id: repository_id.clone(),
            changes: vec![
                merge_change.clone(),
                feature_change.clone(),
                root_change.clone(),
                main_change.clone(),
            ],
            aliases: Vec::new(),
            refs: RepositoryRefState {
                refs: vec![
                    RepositoryRef {
                        repository_id: repository_id.clone(),
                        name: feature,
                        target: RefTarget::change(feature_change.id),
                    },
                    RepositoryRef {
                        repository_id,
                        name: main.clone(),
                        target: RefTarget::change(merge_change.id),
                    },
                ],
                default_ref: Some(main.clone()),
            },
            head: WorkspaceHead::Symbolic { target: main },
            git_authority: None,
        };
        let exported = root.path().join("merge.git");
        let mut loader = StoreLoader { store: &store };
        let result = export_repository_to_git(&plan, &mut loader, &exported).unwrap();
        assert_eq!(result.imported_commits_reused, 0);
        assert_eq!(result.native_commits_written, 4);
        assert_eq!(result.refs_written, 2);

        let oid_for = |change_id| {
            result
                .change_commits
                .iter()
                .find(|binding| binding.change_id == change_id)
                .unwrap()
                .commit_oid
                .to_string()
        };
        let ancestry = String::from_utf8(git_bare(
            &exported,
            &["rev-list", "--parents", "-n", "1", "main"],
        ))
        .unwrap();
        assert_eq!(
            ancestry.split_whitespace().collect::<Vec<_>>(),
            vec![
                oid_for(merge_change.id),
                oid_for(main_change.id),
                oid_for(feature_change.id),
            ]
        );
        assert_eq!(
            tree_blob(&exported, "main", b"compose.yaml"),
            b"services:\n  api:\n    image: main\n"
        );
        assert_eq!(
            tree_blob(&exported, "feature", b"compose.yaml"),
            b"services:\n  api:\n    image: feature\n"
        );
        git_bare(&exported, &["fsck", "--strict"]);
    }

    fn native_change(
        parents: Vec<SemanticChangeId>,
        message: &str,
        tree_deltas: Vec<TreeDelta>,
    ) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("Kin Native"),
            message: message.to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = compute_semantic_change_id(&change).unwrap();
        change
    }

    fn artifact_id(path: &RepoPath) -> ArtifactId {
        ArtifactId(Uuid::new_v5(&Uuid::NAMESPACE_OID, path.as_bytes()))
    }

    fn store_body(store: &BlobStore, body: &[u8]) -> Hash256 {
        let hash = store.write(body).unwrap();
        Hash256::from_bytes(*hash.as_bytes())
    }

    fn write_parent(root: &Path, relative: &str, body: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn add_raw_index_entry(repository: &Path, path: &[u8], body: &[u8]) {
        let oid = String::from_utf8(git_with_input(
            repository,
            &["hash-object", "-w", "--stdin"],
            body,
        ))
        .unwrap();
        let mut entry = format!("100644 blob {}\t", oid.trim()).into_bytes();
        entry.extend_from_slice(path);
        entry.push(0);
        git_with_input(repository, &["update-index", "-z", "--index-info"], &entry);
    }

    fn tree_blob(repository: &Path, revision: &str, path: &[u8]) -> Vec<u8> {
        let listing = git_bare(repository, &["ls-tree", "-rz", revision]);
        let oid = listing
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .find_map(|entry| {
                let separator = entry.iter().position(|byte| *byte == b'\t')?;
                let (metadata, candidate_with_separator) = entry.split_at(separator);
                let candidate = &candidate_with_separator[1..];
                if candidate != path {
                    return None;
                }
                metadata
                    .split(|byte| *byte == b' ')
                    .next_back()
                    .map(|oid| String::from_utf8(oid.to_vec()).unwrap())
            })
            .unwrap_or_else(|| panic!("missing raw Git path {}", hex::encode(path)));
        git_bare(repository, &["cat-file", "blob", &oid])
    }

    fn git(repository: &Path, args: &[&str]) -> Vec<u8> {
        command(fixture_git().args(args).current_dir(repository))
    }

    fn git_bare(repository: &Path, args: &[&str]) -> Vec<u8> {
        let mut invocation = fixture_git();
        invocation.arg("--git-dir").arg(repository).args(args);
        command(&mut invocation)
    }

    fn git_with_input(repository: &Path, args: &[&str], input: &[u8]) -> Vec<u8> {
        let output = fixture_git()
            .args(args)
            .current_dir(repository)
            .output_with_input(input)
            .unwrap();
        assert!(
            output.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn git_clone_without_checkout(source: &Path, destination: &Path) {
        let mut invocation = fixture_git();
        invocation
            .arg("clone")
            .arg("--no-checkout")
            .arg(source)
            .arg(destination);
        command(&mut invocation);
    }

    fn command(invocation: &mut FixtureGitCommand) -> Vec<u8> {
        let output = invocation.output().unwrap();
        assert!(
            output.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }
}
