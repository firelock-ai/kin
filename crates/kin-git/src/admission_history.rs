// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Branch-versioned shared admission policy for exact Git history import.
//!
//! Policy sources are derived exclusively from graph-resolved commit trees and
//! verified CAS bodies. The source repository and working tree are never read
//! at this boundary.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use kin_blobs::BlobStore;
use kin_model::{
    compute_semantic_change_id, validate_semantic_change_id, AdmissionPolicyDelta,
    AdmissionRuleSource, AdmissionRuleSourceKind, AuthorId, ChangeOrigin, DefaultRefMutation,
    ExternalChangeAlias, ExternalObjectRecord, GitObjectId, OperationId, RefMutation, RepositoryId,
    RepositoryRefState, RepositoryTransaction, ResolvedTree, RootBundle, SemanticChange,
    SemanticChangeId, SharedAdmissionPolicy, TreeEntry, WorkspaceHead,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::error::{GitError, Result};
use crate::lossless::{GitObjectFormat, LosslessGitRepository};
use crate::semantic_import::{plan_semantic_git_import, GitWorkspaceSeed, SemanticGitImportPlan};

/// A deterministic semantic Git import whose every commit carries the exact
/// shared admission-policy transition derived from that commit's resolved
/// tree.
///
/// `changes` and `aliases` replace the pre-admission identities in
/// [`SemanticGitImportPlan`]. Raw object records, raw refs/HEAD, resolved
/// commit trees, and workspace seed remain byte-for-byte identical.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedSemanticGitImportPlan {
    pub repository_id: RepositoryId,
    pub object_format: GitObjectFormat,
    pub external_objects: Vec<ExternalObjectRecord>,
    pub changes: Vec<SemanticChange>,
    pub aliases: Vec<ExternalChangeAlias>,
    pub commit_trees: BTreeMap<GitObjectId, ResolvedTree>,
    /// Effective shared policy at every imported commit.
    pub commit_policies: BTreeMap<GitObjectId, SharedAdmissionPolicy>,
    pub refs: RepositoryRefState,
    pub head: WorkspaceHead,
    pub workspace_seed: GitWorkspaceSeed,
    /// Effective policy at the peeled workspace base commit, or canonical
    /// generation-zero empty policy for an unborn workspace.
    pub workspace_policy: SharedAdmissionPolicy,
    /// Admitted semantic identity corresponding to the peeled workspace base.
    /// `None` denotes an unborn workspace.
    pub workspace_base_change_id: Option<SemanticChangeId>,
    pub ref_mutations: Vec<RefMutation>,
    pub default_ref_mutation: Option<DefaultRefMutation>,
}

impl AdmittedSemanticGitImportPlan {
    /// Effective shared policy for the workspace base tree.
    pub const fn workspace_policy(&self) -> &SharedAdmissionPolicy {
        &self.workspace_policy
    }

    /// Admitted semantic change corresponding to the workspace base commit.
    pub const fn workspace_base_change_id(&self) -> Option<SemanticChangeId> {
        self.workspace_base_change_id
    }

    /// Rebuild from the exact raw object/ref state and require the complete
    /// admitted history, policy states, trees, and aliases to match.
    pub fn validate(&self, blob_store: &BlobStore) -> Result<()> {
        let snapshot = LosslessGitRepository {
            repository_id: self.repository_id.clone(),
            object_format: self.object_format,
            objects: self.external_objects.clone(),
            refs: self.refs.clone(),
            head: self.head.clone(),
        };
        let semantic = plan_semantic_git_import(&snapshot, blob_store)?;
        let mut by_oid = BTreeMap::new();
        for change in &self.changes {
            let ChangeOrigin::GitCommit { oid } = change.origin else {
                return Err(GitError::InvalidSnapshot(
                    "admitted semantic Git import contains a native-origin change".to_string(),
                ));
            };
            if by_oid.insert(oid, change).is_some() {
                return Err(GitError::InvalidSnapshot(format!(
                    "admitted semantic Git import repeats commit {oid}"
                )));
            }
        }
        let deltas = semantic
            .changes
            .iter()
            .map(|base_change| {
                let ChangeOrigin::GitCommit { oid } = base_change.origin else {
                    unreachable!("the exact Git planner only emits Git-origin changes");
                };
                let admitted = by_oid.get(&oid).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "admitted semantic Git import is missing commit {oid}"
                    ))
                })?;
                Ok((
                    base_change.id,
                    admitted.entity_deltas.clone(),
                    admitted.relation_deltas.clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let semantic = semantic.with_historical_semantics(blob_store, &deltas)?;
        drop(deltas);

        // Compared commit by commit as the admitted history is re-derived, and
        // each derived commit dropped once checked. Same values, same
        // parent-first order, same refusal; what it no longer does is build a
        // second whole admitted history, at the one moment in the ladder where
        // the working set is already largest, to check the first.
        let mut checked = 0usize;
        let mut mismatch = false;
        let derived =
            derive_admitted_semantic_git_history(&semantic, blob_store, &mut |_oid, admitted, alias| {
                if self.changes.get(checked) != Some(&admitted)
                    || self.aliases.get(checked) != Some(&alias)
                {
                    mismatch = true;
                }
                checked += 1;
                Ok(())
            })?;

        if mismatch
            || checked != derived.commits
            || self.changes.len() != derived.commits
            || self.aliases.len() != derived.commits
            || self.commit_policies != derived.commit_policies
            || self.workspace_policy != derived.workspace_policy
            || self.workspace_base_change_id != derived.workspace_base_change_id
            || self.repository_id != semantic.repository_id
            || self.object_format != semantic.object_format
            || self.external_objects != semantic.external_objects
            || self.commit_trees != semantic.commit_trees
            || self.refs != semantic.refs
            || self.head != semantic.head
            || self.workspace_seed != semantic.workspace_seed
            || self.ref_mutations != semantic.ref_mutations
            || self.default_ref_mutation != semantic.default_ref_mutation
        {
            return Err(GitError::InvalidSnapshot(
                "admitted semantic Git import plan does not match its deterministic raw-object, tree, and CAS derivation"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Bind this fully admitted history to an empty repository authority.
    ///
    /// This method deliberately leaves workspace mutation and Git external
    /// authority unset. The generation-zero integration layer binds the
    /// separately validated workspace preflight and exact Git-authority delta
    /// into the same transaction.
    pub fn into_generation_zero_repository_transaction(
        self,
        blob_store: &BlobStore,
        operation_id: OperationId,
        expected_roots: RootBundle,
        actor: AuthorId,
        reason: impl Into<String>,
    ) -> Result<RepositoryTransaction> {
        self.validate(blob_store)?;
        if expected_roots.generation != 0 {
            return Err(GitError::InvalidSnapshot(format!(
                "admitted Git bootstrap requires generation-zero roots, not generation {}",
                expected_roots.generation
            )));
        }
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id,
            repository_id: self.repository_id,
            expected_generation: 0,
            expected_roots,
            actor,
            reason: reason.into(),
            external_objects: self.external_objects,
            git_authority_delta: None,
            changes: self.changes,
            aliases: self.aliases,
            ref_mutations: self.ref_mutations,
            default_ref_mutation: self.default_ref_mutation,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        transaction.validate()?;
        Ok(transaction)
    }
}

/// Add exact, history-versioned shared admission policy to a validated
/// semantic Git import without consulting the filesystem.
pub fn admit_semantic_git_import(
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
) -> Result<AdmittedSemanticGitImportPlan> {
    plan.validate(blob_store)?;
    build_admitted_semantic_git_import_plan(plan, blob_store)
}

/// What an admitted derivation still holds once every commit has been visited.
struct DerivedAdmittedHistory {
    commit_policies: BTreeMap<GitObjectId, SharedAdmissionPolicy>,
    workspace_policy: SharedAdmissionPolicy,
    workspace_base_change_id: Option<SemanticChangeId>,
    commits: usize,
}

/// Derive branch-versioned admission policy for every imported commit, handing
/// each admitted change and alias to `visit` in parent-first order.
///
/// Same arrangement as the exact planner: building the admitted plan and
/// re-deriving one to check it against are the same walk with different
/// visitors, so they cannot drift, and only the visitor decides what survives
/// the commit it was handed. The policy map stays whole because a commit
/// resolves against its first parent's policy and the workspace seed peels to
/// one; it is the small structure here, where the admitted changes are the
/// history-sized one.
fn derive_admitted_semantic_git_history(
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
    visit: &mut dyn FnMut(GitObjectId, SemanticChange, ExternalChangeAlias) -> Result<()>,
) -> Result<DerivedAdmittedHistory> {
    let mut old_id_to_oid = BTreeMap::<SemanticChangeId, GitObjectId>::new();
    for alias in &plan.aliases {
        if old_id_to_oid.insert(alias.change_id, alias.oid).is_some() {
            return Err(GitError::InvalidSnapshot(format!(
                "pre-admission semantic identity {} maps to more than one Git commit",
                alias.change_id
            )));
        }
    }

    let mut new_change_ids = BTreeMap::<GitObjectId, SemanticChangeId>::new();
    let mut policies = BTreeMap::<GitObjectId, SharedAdmissionPolicy>::new();
    let mut derived = 0usize;

    for original in &plan.changes {
        let oid = match original.origin {
            ChangeOrigin::GitCommit { oid } => oid,
            ChangeOrigin::Native => {
                return Err(GitError::InvalidSnapshot(
                    "semantic Git import contains a native-origin change".to_string(),
                ))
            }
        };
        let parent_oids = original
            .parents
            .iter()
            .map(|parent| {
                old_id_to_oid.get(parent).copied().ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "pre-admission parent {parent} of Git commit {oid} has no external alias"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let first_parent_policy = parent_oids
            .first()
            .map(|parent| {
                policies.get(parent).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "first-parent policy for {parent} was not resolved before commit {oid}"
                    ))
                })
            })
            .transpose()?;
        let tree = plan.commit_trees.get(&oid).ok_or_else(|| {
            GitError::InvalidSnapshot(format!(
                "Git commit {oid} has no graph-resolved tree for admission"
            ))
        })?;
        let sources = admission_sources_for_tree(tree, blob_store)?;
        let (policy, delta) = derive_commit_policy(first_parent_policy, sources)?;
        let parents = parent_oids
            .iter()
            .map(|parent| {
                new_change_ids.get(parent).copied().ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "admitted parent {parent} was not resolved before commit {oid}"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut admitted = original.clone();
        admitted.parents = parents;
        admitted.admission_policy_delta = delta;
        admitted.id = placeholder_change_id();
        admitted.id = compute_semantic_change_id(&admitted)?;
        validate_semantic_change_id(&admitted)?;

        let alias = ExternalChangeAlias::new(plan.repository_id.clone(), oid, admitted.id);
        alias.validate_change(&admitted)?;
        if new_change_ids.insert(oid, admitted.id).is_some()
            || policies.insert(oid, policy).is_some()
        {
            return Err(GitError::InvalidSnapshot(format!(
                "Git commit {oid} appears more than once in admitted history"
            )));
        }
        visit(oid, admitted, alias)?;
        derived += 1;
    }

    if derived != plan.changes.len() || policies.len() != plan.commit_trees.len() {
        return Err(GitError::InvalidSnapshot(
            "not every imported commit produced one admitted change, alias, and policy".to_string(),
        ));
    }

    let (workspace_policy, workspace_base_change_id) = match plan.workspace_seed.base_commit_oid {
        Some(oid) => (
            policies.get(&oid).cloned().ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "workspace base commit {oid} has no admitted policy"
                ))
            })?,
            Some(new_change_ids.get(&oid).copied().ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "workspace base commit {oid} has no admitted semantic identity"
                ))
            })?),
        ),
        None => (SharedAdmissionPolicy::empty(0), None),
    };

    Ok(DerivedAdmittedHistory {
        commit_policies: policies,
        workspace_policy,
        workspace_base_change_id,
        commits: derived,
    })
}

fn build_admitted_semantic_git_import_plan(
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
) -> Result<AdmittedSemanticGitImportPlan> {
    let mut changes = Vec::with_capacity(plan.changes.len());
    let mut aliases = Vec::with_capacity(plan.aliases.len());
    let derived = derive_admitted_semantic_git_history(
        plan,
        blob_store,
        &mut |_oid, admitted, alias| {
            changes.push(admitted);
            aliases.push(alias);
            Ok(())
        },
    )?;
    if changes.len() != plan.changes.len() || aliases.len() != plan.aliases.len() {
        return Err(GitError::InvalidSnapshot(
            "not every imported commit produced one admitted change, alias, and policy".to_string(),
        ));
    }

    Ok(AdmittedSemanticGitImportPlan {
        repository_id: plan.repository_id.clone(),
        object_format: plan.object_format,
        external_objects: plan.external_objects.clone(),
        changes,
        aliases,
        commit_trees: plan.commit_trees.clone(),
        commit_policies: derived.commit_policies,
        refs: plan.refs.clone(),
        head: plan.head.clone(),
        workspace_seed: plan.workspace_seed.clone(),
        workspace_policy: derived.workspace_policy,
        workspace_base_change_id: derived.workspace_base_change_id,
        ref_mutations: plan.ref_mutations.clone(),
        default_ref_mutation: plan.default_ref_mutation.clone(),
    })
}

fn derive_commit_policy(
    first_parent: Option<&SharedAdmissionPolicy>,
    sources: Vec<AdmissionRuleSource>,
) -> Result<(SharedAdmissionPolicy, Option<AdmissionPolicyDelta>)> {
    let Some(old) = first_parent else {
        let policy = SharedAdmissionPolicy::new(0, sources, Vec::new())?;
        let delta = AdmissionPolicyDelta::initialize(policy.clone());
        delta.validate()?;
        return Ok((policy, Some(delta)));
    };

    if old.sources == sources && old.sensitive_allowances.is_empty() {
        // The policy hash intentionally excludes the branch-local generation.
        // Reuse the complete prior state when its semantic content is exact.
        return Ok((old.clone(), None));
    }

    let generation = old.generation.checked_add(1).ok_or_else(|| {
        GitError::InvalidSnapshot("shared admission-policy generation overflow".to_string())
    })?;
    let new = SharedAdmissionPolicy::new(generation, sources, Vec::new())?;
    let delta = AdmissionPolicyDelta::update(old.clone(), new.clone());
    delta.validate()?;
    Ok((new, Some(delta)))
}

fn admission_sources_for_tree(
    tree: &ResolvedTree,
    blob_store: &BlobStore,
) -> Result<Vec<AdmissionRuleSource>> {
    let mut sources = Vec::new();
    for artifact in tree.artifacts() {
        let (base_directory, kind) = match ignore_source_path(&artifact.path)? {
            Some(source) => source,
            None => continue,
        };
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            // Git does not treat a symlink or gitlink named `.gitignore` as a
            // rule file. It remains an exact tree-owned artifact.
            continue;
        };
        let body = blob_store.read(&hash)?;
        let body_len = u64::try_from(body.len()).map_err(|_| {
            GitError::InvalidSnapshot(format!(
                "admission source {} exceeds the supported u64 byte length",
                artifact.path
            ))
        })?;
        sources.push(AdmissionRuleSource {
            kind,
            path: artifact.path.clone(),
            base_directory,
            body_hash: hash,
            body_len,
            precedence: 0,
        });
    }

    sources.sort_by(compare_sources);
    for (index, source) in sources.iter_mut().enumerate() {
        source.precedence = u32::try_from(index).map_err(|_| {
            GitError::InvalidSnapshot("shared admission source count exceeds u32".to_string())
        })?;
    }
    Ok(sources)
}

fn ignore_source_path(
    path: &kin_model::RepoPath,
) -> Result<Option<(Option<kin_model::RepoPath>, AdmissionRuleSourceKind)>> {
    let bytes = path.as_bytes();
    let (base, name) = match bytes.iter().rposition(|byte| *byte == b'/') {
        Some(separator) => (Some(&bytes[..separator]), &bytes[separator + 1..]),
        None => (None, bytes),
    };
    let kind = match name {
        b".gitignore" => AdmissionRuleSourceKind::GitIgnore,
        b".kinignore" => AdmissionRuleSourceKind::KinIgnore,
        _ => return Ok(None),
    };
    let base_directory = base
        .map(kin_model::RepoPath::from_bytes)
        .transpose()
        .map_err(|error| {
            GitError::InvalidSnapshot(format!("invalid admission source base for {path}: {error}"))
        })?;
    Ok(Some((base_directory, kind)))
}

fn compare_sources(left: &AdmissionRuleSource, right: &AdmissionRuleSource) -> Ordering {
    source_depth(left)
        .cmp(&source_depth(right))
        .then_with(|| source_base_bytes(left).cmp(source_base_bytes(right)))
        .then_with(|| source_kind_rank(left.kind).cmp(&source_kind_rank(right.kind)))
        .then_with(|| left.path.as_bytes().cmp(right.path.as_bytes()))
}

fn source_depth(source: &AdmissionRuleSource) -> usize {
    source.base_directory.as_ref().map_or(0, |base| {
        1 + base.as_bytes().iter().filter(|byte| **byte == b'/').count()
    })
}

fn source_base_bytes(source: &AdmissionRuleSource) -> &[u8] {
    source
        .base_directory
        .as_ref()
        .map_or(&[], kin_model::RepoPath::as_bytes)
}

const fn source_kind_rank(kind: AdmissionRuleSourceKind) -> u8 {
    match kind {
        AdmissionRuleSourceKind::GitIgnore => 0,
        AdmissionRuleSourceKind::KinIgnore => 1,
    }
}

fn placeholder_change_id() -> SemanticChangeId {
    SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([0; 32]))
}
