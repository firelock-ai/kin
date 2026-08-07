// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Transaction-ready semantic import derived only from a validated lossless
//! Git snapshot and Kin's blob CAS.
//!
//! This module deliberately has no repository or filesystem input. Git is an
//! ingestion format at this boundary; raw object records remain available for
//! byte-exact projection, while semantic changes and resolved trees become the
//! graph-owned runtime authority.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use kin_blobs::BlobStore;
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, validate_semantic_change_id,
    ArtifactId, AuthorId, ChangeOrigin, DefaultRefExpectation, DefaultRefMutation, EntityDelta,
    ExternalChangeAlias, ExternalObjectId, ExternalObjectKind, ExternalObjectRecord, GitObjectId,
    Hash256, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy, RelationDelta,
    RepositoryId, RepositoryRefState, ResolvedArtifact, ResolvedTree, SemanticChange,
    SemanticChangeId, Timestamp, TreeDelta, TreeEntry, WorkspaceHead,
};
use uuid::Uuid;

use crate::error::{GitError, Result};
use crate::lossless::{validate_snapshot, GitObjectFormat, LosslessGitRepository};

const GIT_ARTIFACT_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0x69, 0x6e, 0x2d, 0x67, 0x69, 0x74, 0x2d, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74,
]);

/// Exact HEAD resolution and committed base tree captured for a later
/// workspace-admission transaction.
///
/// This is intentionally not a `WorkspaceState`: a lossless object/ref
/// snapshot says nothing about an uncommitted index or working directory.
/// Migration preflight must prove those surfaces before treating `base_tree`
/// as the graph-owned workspace tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWorkspaceSeed {
    /// Material workspace HEAD. Symbolic identity is preserved, while a
    /// detached annotated-tag target is normalized to its peeled commit.
    /// Exact raw HEAD identity remains in `GitExternalAuthority`.
    pub head: WorkspaceHead,
    /// Exact material commit target used as the workspace baseline. Annotated
    /// tags are peeled to the commit here; their raw identity remains in
    /// `GitExternalAuthority`. `None` denotes an unborn symbolic HEAD.
    pub base_target: Option<RefTarget>,
    /// Commit reached after peeling any annotated tag target.
    pub base_commit_oid: Option<GitObjectId>,
    /// Resolved committed tree. Empty for an unborn HEAD.
    pub base_tree: ResolvedTree,
    /// Canonical Kin identity of `base_tree`, absent for an unborn HEAD.
    pub base_tree_hash: Option<Hash256>,
}

/// Deterministic, transaction-ready import of one lossless Git snapshot.
///
/// `changes` are parent-first. `commit_trees` contains the exact resolved tree
/// for every imported commit. Ref mutations retain external-object targets so
/// Git can be projected byte-exactly after semantic admission.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticGitImportPlan {
    pub repository_id: RepositoryId,
    pub object_format: GitObjectFormat,
    pub external_objects: Vec<ExternalObjectRecord>,
    pub changes: Vec<SemanticChange>,
    pub aliases: Vec<ExternalChangeAlias>,
    pub commit_trees: BTreeMap<GitObjectId, ResolvedTree>,
    pub refs: RepositoryRefState,
    pub head: WorkspaceHead,
    pub workspace_seed: GitWorkspaceSeed,
    pub ref_mutations: Vec<RefMutation>,
    pub default_ref_mutation: Option<DefaultRefMutation>,
}

impl SemanticGitImportPlan {
    /// Rebuild the plan from its exact raw-object/ref state and require a
    /// byte-for-byte deterministic semantic result.
    pub fn validate(&self, blob_store: &BlobStore) -> Result<()> {
        let snapshot = LosslessGitRepository {
            repository_id: self.repository_id.clone(),
            object_format: self.object_format,
            objects: self.external_objects.clone(),
            refs: self.refs.clone(),
            head: self.head.clone(),
        };
        let base = build_semantic_git_import_plan(&snapshot, blob_store)?;
        let mut by_oid = BTreeMap::new();
        for change in &self.changes {
            let ChangeOrigin::GitCommit { oid } = change.origin else {
                return Err(GitError::InvalidSnapshot(
                    "semantic Git import contains a native-origin change".to_string(),
                ));
            };
            if by_oid.insert(oid, change).is_some() {
                return Err(GitError::InvalidSnapshot(format!(
                    "semantic Git import repeats commit {oid}"
                )));
            }
        }
        let deltas = base
            .changes
            .iter()
            .map(|base_change| {
                let ChangeOrigin::GitCommit { oid } = base_change.origin else {
                    unreachable!("the exact Git planner only emits Git-origin changes");
                };
                let enriched = by_oid.get(&oid).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "semantic Git import is missing enriched commit {oid}"
                    ))
                })?;
                Ok((
                    base_change.id,
                    enriched.entity_deltas.clone(),
                    enriched.relation_deltas.clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let rebuilt = apply_historical_semantic_deltas_unchecked(base, &deltas)?;
        if rebuilt != *self {
            return Err(GitError::InvalidSnapshot(
                "semantic Git import plan does not match its deterministic raw-object derivation"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Bind deterministic CAS-native semantic deltas and recompute every
    /// change identity, parent edge, and external alias in parent-first order.
    pub fn with_historical_semantics(
        self,
        blob_store: &BlobStore,
        deltas: &[(SemanticChangeId, Vec<EntityDelta>, Vec<RelationDelta>)],
    ) -> Result<Self> {
        let snapshot = LosslessGitRepository {
            repository_id: self.repository_id.clone(),
            object_format: self.object_format,
            objects: self.external_objects.clone(),
            refs: self.refs.clone(),
            head: self.head.clone(),
        };
        let exact = build_semantic_git_import_plan(&snapshot, blob_store)?;
        if exact != self {
            return Err(GitError::InvalidSnapshot(
                "historical semantics may only be bound to the exact unenriched import plan"
                    .to_string(),
            ));
        }
        apply_historical_semantic_deltas_unchecked(self, deltas)
    }
}

/// Build semantic Git history using only a lossless snapshot and its CAS.
pub fn plan_semantic_git_import(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
) -> Result<SemanticGitImportPlan> {
    build_semantic_git_import_plan(snapshot, blob_store)
}

fn apply_historical_semantic_deltas_unchecked(
    mut plan: SemanticGitImportPlan,
    deltas: &[(SemanticChangeId, Vec<EntityDelta>, Vec<RelationDelta>)],
) -> Result<SemanticGitImportPlan> {
    let mut delta_by_change = BTreeMap::new();
    for (change_id, entity_deltas, relation_deltas) in deltas {
        if delta_by_change
            .insert(*change_id, (entity_deltas, relation_deltas))
            .is_some()
        {
            return Err(GitError::InvalidSnapshot(format!(
                "historical semantic deltas repeat change {}",
                change_id
            )));
        }
    }
    if delta_by_change.len() != plan.changes.len() {
        return Err(GitError::InvalidSnapshot(format!(
            "historical semantic delta count {} does not match change count {}",
            delta_by_change.len(),
            plan.changes.len()
        )));
    }

    let mut old_to_new = BTreeMap::<SemanticChangeId, SemanticChangeId>::new();
    let mut changes = Vec::with_capacity(plan.changes.len());
    let mut aliases = Vec::with_capacity(plan.changes.len());
    for mut change in plan.changes {
        let old_id = change.id;
        let delta = delta_by_change.remove(&old_id).ok_or_else(|| {
            GitError::InvalidSnapshot(format!("historical semantic deltas omit change {old_id}"))
        })?;
        change.parents = change
            .parents
            .iter()
            .map(|parent| {
                old_to_new.get(parent).copied().ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "parent {parent} was not reidentified before change {old_id}"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        change.entity_deltas = delta.0.clone();
        change.relation_deltas = delta.1.clone();
        change.id = placeholder_change_id();
        change.id = compute_semantic_change_id(&change)?;
        validate_semantic_change_id(&change)?;
        let ChangeOrigin::GitCommit { oid } = change.origin else {
            return Err(GitError::InvalidSnapshot(
                "semantic Git import contains a native-origin change".to_string(),
            ));
        };
        let alias = ExternalChangeAlias::new(plan.repository_id.clone(), oid, change.id);
        alias.validate_change(&change)?;
        old_to_new.insert(old_id, change.id);
        changes.push(change);
        aliases.push(alias);
    }
    if !delta_by_change.is_empty() {
        return Err(GitError::InvalidSnapshot(
            "historical semantic deltas contain unknown changes".to_string(),
        ));
    }
    plan.changes = changes;
    plan.aliases = aliases;
    Ok(plan)
}

#[derive(Debug, Clone)]
struct ParsedCommit {
    tree: GitObjectId,
    parents: Vec<GitObjectId>,
    timestamp: Timestamp,
    author: AuthorId,
    message: String,
}

fn build_semantic_git_import_plan(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
) -> Result<SemanticGitImportPlan> {
    let bodies = validate_snapshot(snapshot, blob_store)?;
    let records = snapshot
        .objects
        .iter()
        .map(|record| (record.object, record))
        .collect::<BTreeMap<_, _>>();
    let hash_kind = gix_hash_kind(snapshot.object_format);
    let commits = parse_commits(snapshot, &bodies, hash_kind)?;
    let order = topological_commit_order(&commits)?;

    let mut tree_decoder = TreeDecoder::new(hash_kind, &bodies, &records);
    for record in snapshot
        .objects
        .iter()
        .filter(|record| record.object.kind == ExternalObjectKind::Tree)
    {
        tree_decoder.decode_relative(record.object.oid)?;
    }

    let mut changes = Vec::with_capacity(order.len());
    let mut aliases = Vec::with_capacity(order.len());
    let mut commit_trees = BTreeMap::new();
    let mut change_ids = BTreeMap::new();
    let mut known_artifact_ids = BTreeSet::new();

    for oid in order {
        let parsed = commits.get(&oid).ok_or_else(|| {
            GitError::InvalidSnapshot(format!("topological order contains unknown commit {oid}"))
        })?;
        let first_parent_tree = match parsed.parents.first() {
            Some(parent) => commit_trees.get(parent).cloned().ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "first parent {parent} was not resolved before commit {oid}"
                ))
            })?,
            None => ResolvedTree::default(),
        };
        let secondary_parent_trees = parsed
            .parents
            .iter()
            .skip(1)
            .map(|parent| {
                commit_trees.get(parent).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "secondary parent {parent} was not resolved before commit {oid}"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let raw_tree = tree_decoder.resolved_entries(parsed.tree)?;
        let resolved_tree = assign_artifact_identities(
            oid,
            &first_parent_tree,
            &secondary_parent_trees,
            raw_tree,
            &known_artifact_ids,
        )?;
        let tree_deltas = exact_tree_deltas(&first_parent_tree, &resolved_tree);
        let applied = first_parent_tree.apply(&tree_deltas).map_err(|error| {
            GitError::InvalidSnapshot(format!(
                "commit {oid} has an invalid first-parent tree transition: {error}"
            ))
        })?;
        if applied != resolved_tree {
            return Err(GitError::InvalidSnapshot(format!(
                "commit {oid} tree deltas do not reconstruct its exact tree"
            )));
        }

        let parents = parsed
            .parents
            .iter()
            .map(|parent| {
                change_ids.get(parent).copied().ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "parent {parent} has no semantic identity before commit {oid}"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut change = SemanticChange {
            id: placeholder_change_id(),
            origin: ChangeOrigin::GitCommit { oid },
            parents,
            timestamp: parsed.timestamp.clone(),
            author: parsed.author.clone(),
            message: parsed.message.clone(),
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
        change.id = compute_semantic_change_id(&change)?;
        validate_semantic_change_id(&change)?;
        let alias = ExternalChangeAlias::new(snapshot.repository_id.clone(), oid, change.id);
        alias.validate_change(&change)?;

        known_artifact_ids.extend(
            resolved_tree
                .artifacts()
                .map(|artifact| artifact.artifact_id),
        );
        change_ids.insert(oid, change.id);
        commit_trees.insert(oid, resolved_tree);
        aliases.push(alias);
        changes.push(change);
    }

    if commit_trees.len() != commits.len()
        || changes.len() != commits.len()
        || aliases.len() != commits.len()
    {
        return Err(GitError::InvalidSnapshot(
            "not every reachable Git commit produced one tree, change, and alias".to_string(),
        ));
    }

    let workspace_seed = resolve_workspace_seed(snapshot, &bodies, hash_kind, &commit_trees)?;
    let ref_mutations = snapshot
        .refs
        .refs
        .iter()
        .map(|repository_ref| {
            Ok(RefMutation {
                name: repository_ref.name.clone(),
                expected: RefExpectation::MustNotExist,
                new_target: Some(material_ref_target(
                    &repository_ref.target,
                    &bodies,
                    hash_kind,
                )?),
                policy: RefUpdatePolicy::ForceWithLease,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for mutation in &ref_mutations {
        mutation.validate()?;
    }
    let default_ref_mutation =
        snapshot
            .refs
            .default_ref
            .as_ref()
            .map(|default_ref| DefaultRefMutation {
                expected: DefaultRefExpectation::MustBeUnset,
                new_default: Some(default_ref.clone()),
            });
    if let Some(mutation) = &default_ref_mutation {
        mutation.validate()?;
    }

    Ok(SemanticGitImportPlan {
        repository_id: snapshot.repository_id.clone(),
        object_format: snapshot.object_format,
        external_objects: snapshot.objects.clone(),
        changes,
        aliases,
        commit_trees,
        refs: snapshot.refs.clone(),
        head: snapshot.head.clone(),
        workspace_seed,
        ref_mutations,
        default_ref_mutation,
    })
}

fn parse_commits(
    snapshot: &LosslessGitRepository,
    bodies: &BTreeMap<ExternalObjectId, Vec<u8>>,
    hash_kind: gix::hash::Kind,
) -> Result<BTreeMap<GitObjectId, ParsedCommit>> {
    let mut commits = BTreeMap::new();
    for record in snapshot
        .objects
        .iter()
        .filter(|record| record.object.kind == ExternalObjectKind::Commit)
    {
        let body = bodies
            .get(&record.object)
            .ok_or_else(|| GitError::MissingObject {
                oid: record.object.oid.to_string(),
                context: "semantic commit decoding".to_string(),
            })?;
        let commit = gix::objs::CommitRef::from_bytes(body, hash_kind).map_err(|error| {
            GitError::InvalidSnapshot(format!("decode commit {}: {error}", record.object.oid))
        })?;
        let parsed = ParsedCommit {
            tree: git_object_id(commit.tree())?,
            parents: commit
                .parents()
                .map(git_object_id)
                .collect::<Result<Vec<_>>>()?,
            timestamp: normalized_timestamp(commit.time().ok().map(|time| time.seconds)),
            author: AuthorId::new(normalize_display_bytes(
                b"git-author-v1:",
                commit.author.as_ref(),
            )),
            message: normalize_display_bytes(b"git-message-v1:", commit.message.as_ref()),
        };
        if commits.insert(record.object.oid, parsed).is_some() {
            return Err(GitError::InvalidSnapshot(format!(
                "duplicate parsed commit {}",
                record.object.oid
            )));
        }
    }
    Ok(commits)
}

fn topological_commit_order(
    commits: &BTreeMap<GitObjectId, ParsedCommit>,
) -> Result<Vec<GitObjectId>> {
    let mut indegree = commits
        .keys()
        .copied()
        .map(|oid| (oid, 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut children = BTreeMap::<GitObjectId, BTreeSet<GitObjectId>>::new();

    for (oid, commit) in commits {
        let unique_parents = commit.parents.iter().copied().collect::<BTreeSet<_>>();
        for parent in &unique_parents {
            if !commits.contains_key(parent) {
                return Err(GitError::MissingObject {
                    oid: parent.to_string(),
                    context: format!("parent of semantic import commit {oid}"),
                });
            }
            children.entry(*parent).or_default().insert(*oid);
        }
        indegree.insert(*oid, unique_parents.len());
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(oid, degree)| (*degree == 0).then_some(*oid))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(commits.len());
    while let Some(oid) = ready.pop_first() {
        ordered.push(oid);
        if let Some(commit_children) = children.get(&oid) {
            for child in commit_children {
                let degree = indegree.get_mut(child).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "commit graph contains unknown child {child}"
                    ))
                })?;
                *degree = degree.checked_sub(1).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "commit graph indegree underflow for {child}"
                    ))
                })?;
                if *degree == 0 {
                    ready.insert(*child);
                }
            }
        }
    }
    if ordered.len() != commits.len() {
        return Err(GitError::InvalidSnapshot(
            "reachable Git commit graph is cyclic".to_string(),
        ));
    }
    Ok(ordered)
}

struct TreeDecoder<'a> {
    hash_kind: gix::hash::Kind,
    bodies: &'a BTreeMap<ExternalObjectId, Vec<u8>>,
    records: &'a BTreeMap<ExternalObjectId, &'a ExternalObjectRecord>,
    cache: BTreeMap<GitObjectId, BTreeMap<Vec<u8>, TreeEntry>>,
    active: BTreeSet<GitObjectId>,
}

impl<'a> TreeDecoder<'a> {
    fn new(
        hash_kind: gix::hash::Kind,
        bodies: &'a BTreeMap<ExternalObjectId, Vec<u8>>,
        records: &'a BTreeMap<ExternalObjectId, &'a ExternalObjectRecord>,
    ) -> Self {
        Self {
            hash_kind,
            bodies,
            records,
            cache: BTreeMap::new(),
            active: BTreeSet::new(),
        }
    }

    fn resolved_entries(
        &mut self,
        tree_oid: GitObjectId,
    ) -> Result<BTreeMap<kin_model::RepoPath, TreeEntry>> {
        self.decode_relative(tree_oid)?
            .into_iter()
            .map(|(path, entry)| {
                kin_model::RepoPath::from_bytes(path)
                    .map(|path| (path, entry))
                    .map_err(|error| {
                        GitError::InvalidSnapshot(format!(
                            "invalid path in tree {tree_oid}: {error}"
                        ))
                    })
            })
            .collect()
    }

    fn decode_relative(&mut self, tree_oid: GitObjectId) -> Result<BTreeMap<Vec<u8>, TreeEntry>> {
        if let Some(cached) = self.cache.get(&tree_oid) {
            return Ok(cached.clone());
        }
        if !self.active.insert(tree_oid) {
            return Err(GitError::InvalidSnapshot(format!(
                "Git tree graph contains a cycle at {tree_oid}"
            )));
        }

        let result = (|| {
            let object = ExternalObjectId::new(ExternalObjectKind::Tree, tree_oid);
            let body =
                self.bodies
                    .get(&object)
                    .cloned()
                    .ok_or_else(|| GitError::MissingObject {
                        oid: tree_oid.to_string(),
                        context: "semantic tree decoding".to_string(),
                    })?;
            let tree = gix::objs::TreeRef::from_bytes(&body, self.hash_kind).map_err(|error| {
                GitError::InvalidSnapshot(format!("decode tree {tree_oid}: {error}"))
            })?;
            let mut entries = BTreeMap::new();
            for entry in tree.entries {
                let entry_oid = git_object_id(entry.oid.to_owned())?;
                match entry.mode.kind() {
                    gix::objs::tree::EntryKind::Tree => {
                        let children = self.decode_relative(entry_oid)?;
                        for (child_path, child_entry) in children {
                            let mut path =
                                Vec::with_capacity(entry.filename.len() + 1 + child_path.len());
                            path.extend_from_slice(entry.filename);
                            path.push(b'/');
                            path.extend_from_slice(&child_path);
                            if entries.insert(path.clone(), child_entry).is_some() {
                                return Err(GitError::InvalidSnapshot(format!(
                                    "tree {tree_oid} repeats path {}",
                                    display_path(&path)
                                )));
                            }
                        }
                    }
                    gix::objs::tree::EntryKind::Blob => {
                        insert_leaf(
                            &mut entries,
                            tree_oid,
                            entry.filename,
                            self.blob_entry(entry_oid, false)?,
                        )?;
                    }
                    gix::objs::tree::EntryKind::BlobExecutable => {
                        insert_leaf(
                            &mut entries,
                            tree_oid,
                            entry.filename,
                            self.blob_entry(entry_oid, true)?,
                        )?;
                    }
                    gix::objs::tree::EntryKind::Link => {
                        let record = self.blob_record(entry_oid)?;
                        insert_leaf(
                            &mut entries,
                            tree_oid,
                            entry.filename,
                            TreeEntry::symlink(record.body_hash),
                        )?;
                    }
                    gix::objs::tree::EntryKind::Commit if entry.mode.value() == 0o160000 => {
                        insert_leaf(
                            &mut entries,
                            tree_oid,
                            entry.filename,
                            TreeEntry::gitlink(entry_oid),
                        )?;
                    }
                    gix::objs::tree::EntryKind::Commit => {
                        return Err(GitError::InvalidSnapshot(format!(
                            "tree {tree_oid} contains unsupported mode {:#o}",
                            entry.mode.value()
                        )));
                    }
                }
            }
            Ok(entries)
        })();
        self.active.remove(&tree_oid);
        if let Ok(entries) = &result {
            self.cache.insert(tree_oid, entries.clone());
        }
        result
    }

    fn blob_entry(&self, oid: GitObjectId, executable: bool) -> Result<TreeEntry> {
        Ok(TreeEntry::blob(
            self.blob_record(oid)?.body_hash,
            executable,
        ))
    }

    fn blob_record(&self, oid: GitObjectId) -> Result<&ExternalObjectRecord> {
        let object = ExternalObjectId::new(ExternalObjectKind::Blob, oid);
        self.records
            .get(&object)
            .copied()
            .ok_or_else(|| GitError::MissingObject {
                oid: oid.to_string(),
                context: "blob referenced by semantic tree".to_string(),
            })
    }
}

fn insert_leaf(
    entries: &mut BTreeMap<Vec<u8>, TreeEntry>,
    tree_oid: GitObjectId,
    filename: &[u8],
    entry: TreeEntry,
) -> Result<()> {
    if entries.insert(filename.to_vec(), entry).is_some() {
        return Err(GitError::InvalidSnapshot(format!(
            "tree {tree_oid} repeats path {}",
            display_path(filename)
        )));
    }
    Ok(())
}

fn assign_artifact_identities(
    introducing_commit: GitObjectId,
    first_parent: &ResolvedTree,
    secondary_parents: &[&ResolvedTree],
    raw_tree: BTreeMap<kin_model::RepoPath, TreeEntry>,
    known_artifact_ids: &BTreeSet<ArtifactId>,
) -> Result<ResolvedTree> {
    let mut addition_counts = HashMap::<TreeEntry, usize>::new();
    for (path, entry) in &raw_tree {
        if first_parent.artifact_at_path(path).is_none() {
            *addition_counts.entry(*entry).or_default() += 1;
        }
    }
    let mut secondary_candidates = HashMap::<TreeEntry, BTreeSet<ArtifactId>>::new();
    for parent in secondary_parents {
        for artifact in parent.artifacts() {
            secondary_candidates
                .entry(artifact.entry)
                .or_default()
                .insert(artifact.artifact_id);
        }
    }
    let reserved_first_parent_ids = raw_tree
        .keys()
        .filter_map(|path| {
            first_parent
                .artifact_at_path(path)
                .map(|artifact| artifact.artifact_id)
        })
        .collect::<BTreeSet<_>>();
    let mut candidate_target_counts = BTreeMap::<ArtifactId, usize>::new();
    for (path, entry) in &raw_tree {
        if first_parent.artifact_at_path(path).is_some() {
            continue;
        }
        if let Some(candidates) = secondary_candidates.get(entry) {
            for candidate in candidates {
                *candidate_target_counts.entry(*candidate).or_default() += 1;
            }
        }
    }

    let mut assigned = BTreeSet::new();
    let mut artifacts = Vec::with_capacity(raw_tree.len());
    for (path, entry) in raw_tree {
        let artifact_id = if let Some(first_parent_artifact) = first_parent.artifact_at_path(&path)
        {
            first_parent_artifact.artifact_id
        } else {
            let candidate = (addition_counts.get(&entry) == Some(&1))
                .then(|| secondary_candidates.get(&entry))
                .flatten()
                .filter(|candidates| candidates.len() == 1)
                .and_then(|candidates| candidates.first().copied())
                .filter(|candidate| {
                    candidate_target_counts.get(candidate) == Some(&1)
                        && !reserved_first_parent_ids.contains(candidate)
                        && !assigned.contains(candidate)
                });
            match candidate {
                Some(candidate) => candidate,
                None => {
                    let derived = introduced_artifact_id(introducing_commit, &path);
                    if known_artifact_ids.contains(&derived) || assigned.contains(&derived) {
                        return Err(GitError::InvalidSnapshot(format!(
                            "deterministic artifact identity collision at {} in commit {}",
                            path, introducing_commit
                        )));
                    }
                    derived
                }
            }
        };
        if !assigned.insert(artifact_id) {
            return Err(GitError::InvalidSnapshot(format!(
                "artifact identity {artifact_id:?} is assigned to more than one path in commit {introducing_commit}"
            )));
        }
        artifacts.push(ResolvedArtifact::new(artifact_id, path, entry));
    }

    ResolvedTree::from_artifacts(artifacts).map_err(|error| {
        GitError::InvalidSnapshot(format!(
            "commit {introducing_commit} resolved tree is invalid: {error}"
        ))
    })
}

/// Derive the identity of an artifact from the content event that introduced
/// it: the commit that first carried the path, and the path itself.
///
/// The commit id already addresses the whole tree and history behind it, so two
/// admissions of one repository derive one identity and their trees, changes,
/// and history root agree by hash rather than by structural walk. This
/// deliberately excludes the repository identity, which `KinManifest::new`
/// mints fresh per admission: including it made every derived id a function of
/// which copy of a repository happened to observe the content, which is the
/// opposite of content addressing and is what left two clones unable to agree
/// on a single graph root.
///
/// Keyed on the *introducing* commit rather than the current path, so identity
/// survives a rename — the property that makes an artifact id worth carrying at
/// all rather than just using the path.
///
/// Two repositories deriving one id means they share the commit and the path,
/// so they hold the same content under the same identity, which is the intended
/// answer rather than a collision. Identity that must not be shared is refused
/// against `known_artifact_ids` at the call site.
fn introduced_artifact_id(commit_oid: GitObjectId, path: &kin_model::RepoPath) -> ArtifactId {
    let mut name = Vec::new();
    append_identity_field(&mut name, commit_oid.as_bytes());
    append_identity_field(&mut name, path.as_bytes());
    ArtifactId(Uuid::new_v5(&GIT_ARTIFACT_NAMESPACE, &name))
}

fn append_identity_field(target: &mut Vec<u8>, field: &[u8]) {
    target.extend_from_slice(
        &u64::try_from(field.len())
            .expect("repository identifiers, Git object IDs, and paths fit in u64")
            .to_le_bytes(),
    );
    target.extend_from_slice(field);
}

fn exact_tree_deltas(base: &ResolvedTree, target: &ResolvedTree) -> Vec<TreeDelta> {
    let mut deltas = Vec::new();
    for old in base.artifacts() {
        match target.get(&old.artifact_id) {
            Some(new) if old.path == new.path && old.entry == new.entry => {}
            Some(new) => deltas.push(TreeDelta::Updated {
                artifact_id: old.artifact_id,
                old: old.located_entry(),
                new: new.located_entry(),
            }),
            None => deltas.push(TreeDelta::Removed {
                artifact_id: old.artifact_id,
                old: old.located_entry(),
            }),
        }
    }
    for new in target.artifacts() {
        if base.get(&new.artifact_id).is_none() {
            deltas.push(TreeDelta::Added {
                artifact_id: new.artifact_id,
                new: new.located_entry(),
            });
        }
    }
    deltas.sort_by_key(TreeDelta::artifact_id);
    deltas
}

fn resolve_workspace_seed(
    snapshot: &LosslessGitRepository,
    bodies: &BTreeMap<ExternalObjectId, Vec<u8>>,
    hash_kind: gix::hash::Kind,
    commit_trees: &BTreeMap<GitObjectId, ResolvedTree>,
) -> Result<GitWorkspaceSeed> {
    let refs = snapshot
        .refs
        .refs
        .iter()
        .map(|repository_ref| (repository_ref.name.clone(), repository_ref.target.clone()))
        .collect::<BTreeMap<_, _>>();
    let base_target = match &snapshot.head {
        WorkspaceHead::Symbolic { target } => resolve_symbolic_target(target, &refs)?,
        WorkspaceHead::Detached { target } => Some(target.clone()),
    };
    let Some(base_target) = base_target else {
        return Ok(GitWorkspaceSeed {
            head: snapshot.head.clone(),
            base_target: None,
            base_commit_oid: None,
            base_tree: ResolvedTree::default(),
            base_tree_hash: None,
        });
    };
    let object = match &base_target {
        RefTarget::ExternalObject { object } => *object,
        RefTarget::Change { change_id } => {
            return Err(GitError::InvalidSnapshot(format!(
                "lossless Git HEAD resolves to native change {change_id}"
            )))
        }
        RefTarget::Symbolic { .. } => {
            return Err(GitError::InvalidSnapshot(
                "HEAD resolution ended at a symbolic target".to_string(),
            ))
        }
    };
    let base_commit_oid = peel_to_commit(object, bodies, hash_kind)?;
    let base_tree =
        commit_trees
            .get(&base_commit_oid)
            .cloned()
            .ok_or_else(|| GitError::MissingObject {
                oid: base_commit_oid.to_string(),
                context: "resolved HEAD commit tree".to_string(),
            })?;
    let base_tree_hash = compute_resolved_tree_hash(&base_tree)?;
    let material_target = RefTarget::external_object(ExternalObjectId::new(
        ExternalObjectKind::Commit,
        base_commit_oid,
    ));
    let workspace_head = match &snapshot.head {
        WorkspaceHead::Symbolic { .. } => snapshot.head.clone(),
        WorkspaceHead::Detached { .. } => WorkspaceHead::Detached {
            target: material_target.clone(),
        },
    };
    Ok(GitWorkspaceSeed {
        head: workspace_head,
        base_target: Some(material_target),
        base_commit_oid: Some(base_commit_oid),
        base_tree,
        base_tree_hash: Some(base_tree_hash),
    })
}

fn resolve_symbolic_target(
    start: &RefName,
    refs: &BTreeMap<RefName, RefTarget>,
) -> Result<Option<RefTarget>> {
    let mut current = start.clone();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.clone()) {
            return Err(GitError::InvalidSnapshot(format!(
                "symbolic HEAD/ref cycle reaches {current}"
            )));
        }
        let Some(target) = refs.get(&current) else {
            return Ok(None);
        };
        match target {
            RefTarget::Symbolic { target } => current = target.clone(),
            RefTarget::ExternalObject { .. } => return Ok(Some(target.clone())),
            RefTarget::Change { change_id } => {
                return Err(GitError::InvalidSnapshot(format!(
                    "lossless Git ref {current} targets native change {change_id}"
                )))
            }
        }
    }
}

fn peel_to_commit(
    start: ExternalObjectId,
    bodies: &BTreeMap<ExternalObjectId, Vec<u8>>,
    hash_kind: gix::hash::Kind,
) -> Result<GitObjectId> {
    let current = peel_annotated_tags(start, bodies, hash_kind)?;
    match current.kind {
        ExternalObjectKind::Commit => Ok(current.oid),
        ExternalObjectKind::Tree | ExternalObjectKind::Blob => {
            Err(GitError::InvalidSnapshot(format!(
                "HEAD target {} is a {:?}, not a commit-ish object",
                current.oid, current.kind
            )))
        }
        ExternalObjectKind::Tag => unreachable!("annotated tags are peeled completely"),
    }
}

fn material_ref_target(
    target: &RefTarget,
    bodies: &BTreeMap<ExternalObjectId, Vec<u8>>,
    hash_kind: gix::hash::Kind,
) -> Result<RefTarget> {
    let RefTarget::ExternalObject { object } = target else {
        return Ok(target.clone());
    };
    if object.kind != ExternalObjectKind::Tag {
        return Ok(target.clone());
    }
    let peeled = peel_annotated_tags(*object, bodies, hash_kind)?;
    Ok(if peeled.kind == ExternalObjectKind::Commit {
        RefTarget::external_object(peeled)
    } else {
        target.clone()
    })
}

fn peel_annotated_tags(
    start: ExternalObjectId,
    bodies: &BTreeMap<ExternalObjectId, Vec<u8>>,
    hash_kind: gix::hash::Kind,
) -> Result<ExternalObjectId> {
    let mut current = start;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current) {
            return Err(GitError::InvalidSnapshot(format!(
                "annotated tag cycle reaches {}",
                current.oid
            )));
        }
        match current.kind {
            ExternalObjectKind::Commit | ExternalObjectKind::Tree | ExternalObjectKind::Blob => {
                return Ok(current)
            }
            ExternalObjectKind::Tag => {
                let body = bodies
                    .get(&current)
                    .ok_or_else(|| GitError::MissingObject {
                        oid: current.oid.to_string(),
                        context: "peeling annotated tag".to_string(),
                    })?;
                let tag = gix::objs::TagRef::from_bytes(body, hash_kind).map_err(|error| {
                    GitError::InvalidSnapshot(format!(
                        "decode annotated tag {}: {error}",
                        current.oid
                    ))
                })?;
                current = ExternalObjectId::new(
                    external_kind(tag.target_kind),
                    git_object_id(tag.target())?,
                );
            }
        }
    }
}

fn placeholder_change_id() -> SemanticChangeId {
    SemanticChangeId::from_hash(Hash256::from_bytes([0; 32]))
}

fn normalized_timestamp(seconds: Option<i64>) -> Timestamp {
    let epoch = DateTime::<Utc>::from_timestamp(0, 0)
        .expect("the Unix epoch is always representable by chrono");
    Timestamp::from(
        seconds
            .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
            .unwrap_or(epoch),
    )
}

fn normalize_display_bytes(prefix: &[u8], bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => format!(
            "{}{}",
            std::str::from_utf8(prefix).expect("normalization prefixes are UTF-8"),
            hex::encode(bytes)
        ),
    }
}

fn gix_hash_kind(object_format: GitObjectFormat) -> gix::hash::Kind {
    match object_format {
        GitObjectFormat::Sha1 => gix::hash::Kind::Sha1,
        GitObjectFormat::Sha256 => gix::hash::Kind::Sha256,
    }
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

fn external_kind(kind: gix::objs::Kind) -> ExternalObjectKind {
    match kind {
        gix::objs::Kind::Commit => ExternalObjectKind::Commit,
        gix::objs::Kind::Tree => ExternalObjectKind::Tree,
        gix::objs::Kind::Blob => ExternalObjectKind::Blob,
        gix::objs::Kind::Tag => ExternalObjectKind::Tag,
    }
}

fn display_path(path: &[u8]) -> String {
    match std::str::from_utf8(path) {
        Ok(path) => path.to_string(),
        Err(_) => format!("0x{}", hex::encode(path)),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Output;

    #[cfg(unix)]
    use kin_model::{
        AdmissionRuleSourceKind, AuthorityRoot, OperationId, RootBundle,
        REPOSITORY_ROOT_SCHEMA_VERSION,
    };
    use kin_model::{RepoPath, SharedAdmissionPolicy};
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;
    #[cfg(unix)]
    use tempfile::TempDir;

    use super::*;
    use crate::admission_history::admit_semantic_git_import;
    #[cfg(unix)]
    use crate::admission_history::AdmittedSemanticGitImportPlan;
    use crate::lossless::capture_lossless_git_repository;
    use crate::test_support::fixture_git;

    #[cfg(unix)]
    struct SemanticFixture {
        root: TempDir,
        repo: PathBuf,
        blob_store: BlobStore,
        initial: GitObjectId,
        empty: GitObjectId,
        one: GitObjectId,
        two: GitObjectId,
        three: GitObjectId,
        merge: GitObjectId,
        compose_blob: GitObjectId,
        tool_blob: GitObjectId,
        initial_symlink_blob: GitObjectId,
        symlink_blob: GitObjectId,
        non_utf8_blob: GitObjectId,
        binary_blob: GitObjectId,
        gitlink: GitObjectId,
    }

    #[cfg(unix)]
    impl SemanticFixture {
        fn octopus_polyglot() -> Self {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let root = tempdir().unwrap();
            let repo = root.path().join("source");
            fs::create_dir(&repo).unwrap();
            git_ok(&repo, ["init", "--initial-branch=main"]);
            configure_git(&repo);

            write(&repo, "Cargo.toml", b"[package]\nname = \"mixed\"\n");
            write(&repo, "src/lib.rs", b"pub fn rust_value() -> u8 { 7 }\n");
            write(
                &repo,
                "package.json",
                br#"{"scripts":{"test":"node src/app.ts"}}"#,
            );
            write(&repo, "src/app.ts", b"export const tsValue: number = 8;\n");
            write(
                &repo,
                "pyproject.toml",
                b"[project]\nname = \"mixed-python\"\n",
            );
            write(
                &repo,
                "python/app.py",
                b"def python_value():\n    return 9\n",
            );
            write(
                &repo,
                "compose.yaml",
                b"services:\n  app:\n    build: .\n    environment:\n      MODE: test\n",
            );
            write(
                &repo,
                "Dockerfile",
                b"FROM scratch\nCOPY config/app.yaml /app.yaml\n",
            );
            write(
                &repo,
                ".github/workflows/ci.yml",
                b"name: ci\non: [push]\njobs: {}\n",
            );
            write(&repo, "config/app.yaml", b"feature:\n  enabled: true\n");
            write(
                &repo,
                "NOTICE.txt",
                b"This is unrelated legal and operational text.\n",
            );
            write(
                &repo,
                "unclassified/archive.unknownlang",
                b"opaque unsupported-language source\n",
            );
            write(&repo, ".gitignore", b"*.scratch\n");
            write(&repo, ".kinignore", b".kin-local/\n");
            write(&repo, "config/.gitignore", b"*.generated\n");
            write(&repo, "config/.kinignore", b"private-*.yaml\n");
            write(&repo, "assets/raw.bin", &[0, 255, 1, 128, b'\n', 0, 42]);
            write(&repo, "scripts/tool.sh", b"#!/bin/sh\nprintf 'kin\\n'\n");
            let executable = repo.join("scripts/tool.sh");
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            symlink("config/app.yaml", repo.join("config-link")).unwrap();

            git_ok(&repo, ["add", "--all"]);
            let non_utf8_blob = git_stdin_text(
                &repo,
                ["hash-object", "-w", "--stdin"],
                &[0xde, 0xad, 0xbe, 0xef],
            );
            let mut index_entry = format!("100644 {non_utf8_blob}\t").into_bytes();
            index_entry.extend_from_slice(b"odd-\xff.bin\0");
            git_stdin_ok(&repo, ["update-index", "-z", "--index-info"], &index_entry);
            let gitlink = "4242424242424242424242424242424242424242";
            git_ok(
                &repo,
                [
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("160000,{gitlink},vendor/sub"),
                ],
            );
            git_ok(&repo, ["commit", "-m", "initial exact tree"]);
            let initial = git_text(&repo, ["rev-parse", "HEAD"]);
            let initial_symlink_blob = git_text(&repo, ["rev-parse", "HEAD:config-link"]);

            git_ok(&repo, ["commit", "--allow-empty", "-m", "empty checkpoint"]);
            let empty = git_text(&repo, ["rev-parse", "HEAD"]);

            git_ok(&repo, ["switch", "-c", "one"]);
            write(&repo, "branch-one.txt", b"unique branch one\n");
            write(&repo, "same-a.bin", b"ambiguous shared body\n");
            write(&repo, ".gitignore", b"*.scratch\n*.branch-one\n");
            let executable = repo.join("scripts/tool.sh");
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o644);
            fs::set_permissions(&executable, permissions).unwrap();
            git_ok(
                &repo,
                [
                    "add",
                    "branch-one.txt",
                    "same-a.bin",
                    "scripts/tool.sh",
                    ".gitignore",
                ],
            );
            git_ok(&repo, ["commit", "-m", "branch one"]);
            let one = git_text(&repo, ["rev-parse", "HEAD"]);

            git_ok(&repo, ["switch", "main"]);
            git_ok(&repo, ["switch", "-c", "two"]);
            write(&repo, "branch-two.txt", b"unique branch two\n");
            write(&repo, "same-b.bin", b"ambiguous shared body\n");
            fs::remove_file(repo.join("config/.gitignore")).unwrap();
            write(
                &repo,
                "config/.kinignore",
                b"private-*.yaml\nbranch-two-*.yaml\n",
            );
            fs::remove_file(repo.join("config-link")).unwrap();
            symlink("compose.yaml", repo.join("config-link")).unwrap();
            git_ok(
                &repo,
                [
                    "add",
                    "branch-two.txt",
                    "same-b.bin",
                    "config-link",
                    "config/.gitignore",
                    "config/.kinignore",
                ],
            );
            git_ok(&repo, ["commit", "-m", "branch two"]);
            let two = git_text(&repo, ["rev-parse", "HEAD"]);

            git_ok(&repo, ["switch", "main"]);
            git_ok(&repo, ["switch", "-c", "three"]);
            write(&repo, "branch-three.txt", b"unique branch three\n");
            git_ok(&repo, ["add", "branch-three.txt"]);
            git_ok(&repo, ["commit", "-m", "branch three"]);
            let three = git_text(&repo, ["rev-parse", "HEAD"]);

            git_ok(&repo, ["switch", "main"]);
            git_ok(
                &repo,
                [
                    "merge",
                    "--no-ff",
                    "one",
                    "two",
                    "three",
                    "-m",
                    "octopus merge",
                ],
            );
            let merge = git_text(&repo, ["rev-parse", "HEAD"]);
            let parent_line = git_text(&repo, ["rev-list", "--parents", "-n", "1", "HEAD"]);
            assert_eq!(
                parent_line.split_whitespace().skip(1).collect::<Vec<_>>(),
                [&empty, &one, &two, &three]
            );
            git_ok(&repo, ["tag", "-a", "release-octo", "-m", "annotated"]);
            git_ok(
                &repo,
                ["symbolic-ref", "refs/aliases/stable", "refs/heads/main"],
            );

            let compose_blob = git_text(&repo, ["rev-parse", "HEAD:compose.yaml"]);
            let tool_blob = git_text(&repo, ["rev-parse", "HEAD:scripts/tool.sh"]);
            let symlink_blob = git_text(&repo, ["rev-parse", "HEAD:config-link"]);
            let binary_blob = git_text(&repo, ["rev-parse", "HEAD:assets/raw.bin"]);
            let cas_root = root.path().join("cas");
            let blob_store = BlobStore::new(cas_root.clone()).unwrap();
            Self {
                root,
                repo,
                blob_store,
                initial: model_oid(&initial),
                empty: model_oid(&empty),
                one: model_oid(&one),
                two: model_oid(&two),
                three: model_oid(&three),
                merge: model_oid(&merge),
                compose_blob: model_oid(&compose_blob),
                tool_blob: model_oid(&tool_blob),
                initial_symlink_blob: model_oid(&initial_symlink_blob),
                symlink_blob: model_oid(&symlink_blob),
                non_utf8_blob: model_oid(&non_utf8_blob),
                binary_blob: model_oid(&binary_blob),
                gitlink: model_oid(gitlink),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn plans_exact_polyglot_octopus_history_without_repository_access() {
        let fixture = SemanticFixture::octopus_polyglot();
        let snapshot = capture_lossless_git_repository(
            &fixture.repo,
            RepositoryId::new("semantic-octopus").unwrap(),
            &fixture.blob_store,
        )
        .unwrap();

        let first = plan_semantic_git_import(&snapshot, &fixture.blob_store).unwrap();
        fs::rename(
            &fixture.repo,
            fixture.root.path().join("repository-is-offline"),
        )
        .unwrap();
        let second = plan_semantic_git_import(&snapshot, &fixture.blob_store).unwrap();
        assert_eq!(second, first);
        second.validate(&fixture.blob_store).unwrap();

        assert_eq!(second.changes.len(), 6);
        assert_eq!(second.aliases.len(), 6);
        assert_eq!(second.commit_trees.len(), 6);
        assert!(second.changes.iter().all(|change| {
            matches!(change.origin, ChangeOrigin::GitCommit { .. })
                && change.entity_deltas.is_empty()
                && change.relation_deltas.is_empty()
        }));

        let initial_change = change_for_oid(&second, fixture.initial);
        let empty_change = change_for_oid(&second, fixture.empty);
        let merge_change = change_for_oid(&second, fixture.merge);
        assert_eq!(empty_change.parents, vec![initial_change.id]);
        assert!(empty_change.tree_deltas.is_empty());
        assert_eq!(
            second.commit_trees.get(&fixture.empty),
            second.commit_trees.get(&fixture.initial)
        );
        assert_eq!(
            merge_change.parents,
            [fixture.empty, fixture.one, fixture.two, fixture.three]
                .map(|oid| alias_for_oid(&second, oid).change_id)
        );

        let initial_tree = second.commit_trees.get(&fixture.initial).unwrap();
        let merge_tree = second.commit_trees.get(&fixture.merge).unwrap();
        assert_eq!(
            artifact_id(initial_tree, b"compose.yaml"),
            artifact_id(merge_tree, b"compose.yaml")
        );
        assert_eq!(
            artifact_id(initial_tree, b"scripts/tool.sh"),
            artifact_id(merge_tree, b"scripts/tool.sh")
        );
        assert_eq!(
            artifact_id(initial_tree, b"config-link"),
            artifact_id(merge_tree, b"config-link")
        );
        assert_eq!(
            artifact_id(
                second.commit_trees.get(&fixture.one).unwrap(),
                b"branch-one.txt"
            ),
            artifact_id(merge_tree, b"branch-one.txt")
        );
        let branch_same_a = artifact_id(
            second.commit_trees.get(&fixture.one).unwrap(),
            b"same-a.bin",
        );
        let branch_same_b = artifact_id(
            second.commit_trees.get(&fixture.two).unwrap(),
            b"same-b.bin",
        );
        let merge_same_a = artifact_id(merge_tree, b"same-a.bin");
        let merge_same_b = artifact_id(merge_tree, b"same-b.bin");
        assert_ne!(merge_same_a, branch_same_a);
        assert_ne!(merge_same_a, branch_same_b);
        assert_ne!(merge_same_b, branch_same_a);
        assert_ne!(merge_same_b, branch_same_b);
        assert_ne!(merge_same_a, merge_same_b);

        assert_entry(
            merge_tree,
            b"compose.yaml",
            TreeEntry::blob(body_hash_for_blob(&second, fixture.compose_blob), false),
        );
        assert_entry(
            initial_tree,
            b"scripts/tool.sh",
            TreeEntry::blob(body_hash_for_blob(&second, fixture.tool_blob), true),
        );
        assert_entry(
            merge_tree,
            b"scripts/tool.sh",
            TreeEntry::blob(body_hash_for_blob(&second, fixture.tool_blob), false),
        );
        assert_entry(
            initial_tree,
            b"config-link",
            TreeEntry::symlink(body_hash_for_blob(&second, fixture.initial_symlink_blob)),
        );
        assert_entry(
            merge_tree,
            b"config-link",
            TreeEntry::symlink(body_hash_for_blob(&second, fixture.symlink_blob)),
        );
        assert_entry(
            merge_tree,
            b"odd-\xff.bin",
            TreeEntry::blob(body_hash_for_blob(&second, fixture.non_utf8_blob), false),
        );
        assert_entry(
            merge_tree,
            b"assets/raw.bin",
            TreeEntry::blob(body_hash_for_blob(&second, fixture.binary_blob), false),
        );
        assert_entry(
            merge_tree,
            b"vendor/sub",
            TreeEntry::gitlink(fixture.gitlink),
        );
        let tool_id = artifact_id(merge_tree, b"scripts/tool.sh");
        assert!(merge_change.tree_deltas.iter().any(|delta| {
            matches!(
                delta,
                TreeDelta::Updated {
                    artifact_id,
                    old,
                    new,
                } if *artifact_id == tool_id
                    && old.entry
                        == TreeEntry::blob(
                            body_hash_for_blob(&second, fixture.tool_blob),
                            true,
                        )
                    && new.entry
                        == TreeEntry::blob(
                            body_hash_for_blob(&second, fixture.tool_blob),
                            false,
                        )
            )
        }));
        let symlink_id = artifact_id(merge_tree, b"config-link");
        assert!(merge_change.tree_deltas.iter().any(|delta| {
            matches!(
                delta,
                TreeDelta::Updated {
                    artifact_id,
                    old,
                    new,
                } if *artifact_id == symlink_id
                    && old.entry
                        == TreeEntry::symlink(body_hash_for_blob(
                            &second,
                            fixture.initial_symlink_blob,
                        ))
                    && new.entry
                        == TreeEntry::symlink(body_hash_for_blob(
                            &second,
                            fixture.symlink_blob,
                        ))
            )
        }));
        for path in [
            b"Cargo.toml".as_slice(),
            b"src/lib.rs",
            b"package.json",
            b"src/app.ts",
            b"pyproject.toml",
            b"python/app.py",
            b"Dockerfile",
            b".github/workflows/ci.yml",
            b"config/app.yaml",
            b"NOTICE.txt",
        ] {
            assert!(
                merge_tree.artifact_at_path(&repo_path(path)).is_some(),
                "missing semantic tree entry {}",
                display_path(path)
            );
        }

        assert_eq!(second.refs, snapshot.refs);
        assert_eq!(second.head, snapshot.head);
        assert_eq!(second.ref_mutations.len(), snapshot.refs.refs.len());
        assert!(second.refs.refs.iter().any(|repository_ref| {
            repository_ref.name.as_bytes() == b"refs/tags/release-octo"
                && matches!(
                    repository_ref.target,
                    RefTarget::ExternalObject {
                        object: ExternalObjectId {
                            kind: ExternalObjectKind::Tag,
                            ..
                        }
                    }
                )
        }));
        assert!(second.ref_mutations.iter().any(|mutation| {
            mutation.name.as_bytes() == b"refs/tags/release-octo"
                && matches!(
                    mutation.new_target.as_ref(),
                    Some(RefTarget::ExternalObject {
                        object: ExternalObjectId {
                            kind: ExternalObjectKind::Commit,
                            oid,
                        }
                    }) if *oid == fixture.merge
                )
        }));
        assert_eq!(second.workspace_seed.head, snapshot.head);
        assert_eq!(second.workspace_seed.base_commit_oid, Some(fixture.merge));
        assert_eq!(second.workspace_seed.base_tree, *merge_tree);
        assert_eq!(
            second.workspace_seed.base_tree_hash,
            Some(compute_resolved_tree_hash(merge_tree).unwrap())
        );
        assert!(matches!(
            second.workspace_seed.base_target,
            Some(RefTarget::ExternalObject {
                object: ExternalObjectId {
                    kind: ExternalObjectKind::Commit,
                    oid,
                }
            }) if oid == fixture.merge
        ));
    }

    #[cfg(unix)]
    #[test]
    fn admits_branch_versioned_policy_from_exact_commit_trees_and_cas() {
        let fixture = SemanticFixture::octopus_polyglot();
        let snapshot = capture_lossless_git_repository(
            &fixture.repo,
            RepositoryId::new("semantic-admission-history").unwrap(),
            &fixture.blob_store,
        )
        .unwrap();
        let semantic = plan_semantic_git_import(&snapshot, &fixture.blob_store).unwrap();
        let admitted = admit_semantic_git_import(&semantic, &fixture.blob_store).unwrap();

        fs::rename(
            &fixture.repo,
            fixture.root.path().join("source-remains-offline"),
        )
        .unwrap();
        let replay = admit_semantic_git_import(&semantic, &fixture.blob_store).unwrap();
        assert_eq!(replay, admitted);
        replay.validate(&fixture.blob_store).unwrap();

        assert_eq!(admitted.external_objects, semantic.external_objects);
        assert_eq!(admitted.commit_trees, semantic.commit_trees);
        assert_eq!(admitted.refs, semantic.refs);
        assert_eq!(admitted.head, semantic.head);
        assert_eq!(admitted.workspace_seed, semantic.workspace_seed);
        assert_eq!(admitted.changes.len(), semantic.changes.len());
        assert_eq!(admitted.aliases.len(), semantic.aliases.len());
        assert_eq!(admitted.commit_policies.len(), semantic.commit_trees.len());

        let initial_policy = admitted.commit_policies.get(&fixture.initial).unwrap();
        assert_eq!(initial_policy.generation, 0);
        assert_eq!(
            initial_policy
                .sources
                .iter()
                .map(|source| (
                    source.kind,
                    source.path.as_bytes().to_vec(),
                    source
                        .base_directory
                        .as_ref()
                        .map(|base| base.as_bytes().to_vec()),
                    source.precedence,
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    AdmissionRuleSourceKind::GitIgnore,
                    b".gitignore".to_vec(),
                    None,
                    0,
                ),
                (
                    AdmissionRuleSourceKind::KinIgnore,
                    b".kinignore".to_vec(),
                    None,
                    1,
                ),
                (
                    AdmissionRuleSourceKind::GitIgnore,
                    b"config/.gitignore".to_vec(),
                    Some(b"config".to_vec()),
                    2,
                ),
                (
                    AdmissionRuleSourceKind::KinIgnore,
                    b"config/.kinignore".to_vec(),
                    Some(b"config".to_vec()),
                    3,
                ),
            ]
        );
        for source in &initial_policy.sources {
            let body = fixture.blob_store.read(&source.body_hash).unwrap();
            assert_eq!(source.body_len, u64::try_from(body.len()).unwrap());
            let tree_entry = semantic
                .commit_trees
                .get(&fixture.initial)
                .unwrap()
                .artifact_at_path(&source.path)
                .unwrap()
                .entry;
            assert!(matches!(
                tree_entry,
                TreeEntry::Blob { hash, .. } if hash == source.body_hash
            ));
        }
        let initial_delta = admitted_change_for_oid(&admitted, fixture.initial)
            .admission_policy_delta
            .as_ref()
            .unwrap();
        assert_eq!(initial_delta.old, None);
        assert_eq!(initial_delta.new.as_ref(), Some(initial_policy));

        let empty_policy = admitted.commit_policies.get(&fixture.empty).unwrap();
        assert_eq!(empty_policy, initial_policy);
        assert!(admitted_change_for_oid(&admitted, fixture.empty)
            .admission_policy_delta
            .is_none());
        let branch_three_policy = admitted.commit_policies.get(&fixture.three).unwrap();
        assert_eq!(branch_three_policy, initial_policy);
        assert!(admitted_change_for_oid(&admitted, fixture.three)
            .admission_policy_delta
            .is_none());

        let branch_one_policy = admitted.commit_policies.get(&fixture.one).unwrap();
        assert_eq!(branch_one_policy.generation, 1);
        assert_ne!(branch_one_policy.hash, initial_policy.hash);
        let branch_one_delta = admitted_change_for_oid(&admitted, fixture.one)
            .admission_policy_delta
            .as_ref()
            .unwrap();
        assert_eq!(branch_one_delta.old.as_ref(), Some(initial_policy));
        assert_eq!(branch_one_delta.new.as_ref(), Some(branch_one_policy));

        let branch_two_policy = admitted.commit_policies.get(&fixture.two).unwrap();
        assert_eq!(branch_two_policy.generation, 1);
        assert!(branch_two_policy
            .sources
            .iter()
            .all(|source| source.path.as_bytes() != b"config/.gitignore"));
        assert_eq!(
            branch_two_policy
                .sources
                .iter()
                .find(|source| source.path.as_bytes() == b"config/.kinignore")
                .unwrap()
                .body_len,
            u64::try_from(b"private-*.yaml\nbranch-two-*.yaml\n".len()).unwrap()
        );

        let merge_policy = admitted.commit_policies.get(&fixture.merge).unwrap();
        assert_eq!(merge_policy.generation, 1);
        let merge_delta = admitted_change_for_oid(&admitted, fixture.merge)
            .admission_policy_delta
            .as_ref()
            .unwrap();
        assert_eq!(merge_delta.old.as_ref(), Some(empty_policy));
        assert_eq!(merge_delta.new.as_ref(), Some(merge_policy));
        assert!(merge_policy
            .sources
            .iter()
            .all(|source| source.path.as_bytes() != b"config/.gitignore"));
        assert_eq!(
            admitted_change_for_oid(&admitted, fixture.merge).parents,
            [fixture.empty, fixture.one, fixture.two, fixture.three]
                .map(|oid| admitted_alias_for_oid(&admitted, oid).change_id)
        );

        for original_alias in &semantic.aliases {
            let admitted_alias = admitted_alias_for_oid(&admitted, original_alias.oid);
            assert_ne!(admitted_alias.change_id, original_alias.change_id);
        }
        assert_eq!(admitted.workspace_policy(), merge_policy);
        assert_eq!(
            admitted.workspace_base_change_id(),
            Some(admitted_alias_for_oid(&admitted, fixture.merge).change_id)
        );

        let merge_tree = admitted.commit_trees.get(&fixture.merge).unwrap();
        for path in [
            b"compose.yaml".as_slice(),
            b"assets/raw.bin",
            b"unclassified/archive.unknownlang",
            b"NOTICE.txt",
        ] {
            assert_eq!(
                merge_tree.artifact_at_path(&repo_path(path)),
                semantic
                    .commit_trees
                    .get(&fixture.merge)
                    .unwrap()
                    .artifact_at_path(&repo_path(path)),
                "non-policy artifact changed during admission: {}",
                display_path(path)
            );
        }

        let transaction = admitted
            .clone()
            .into_generation_zero_repository_transaction(
                &fixture.blob_store,
                OperationId::from_uuid(Uuid::from_u128(2)),
                root_bundle(),
                AuthorId::new("admission-history-test"),
                "admit branch-versioned Git history",
            )
            .unwrap();
        assert_eq!(transaction.changes, admitted.changes);
        assert_eq!(transaction.aliases, admitted.aliases);
        assert!(transaction.git_authority_delta.is_none());
        assert!(transaction.workspace_mutation.is_none());
        transaction.validate().unwrap();
    }

    #[test]
    fn unborn_import_has_canonical_empty_workspace_policy() {
        let root = tempdir().unwrap();
        let repo = root.path().join("source");
        fs::create_dir(&repo).unwrap();
        git_ok(&repo, ["init", "--initial-branch=main"]);
        configure_git(&repo);
        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repo,
            RepositoryId::new("semantic-unborn-admission").unwrap(),
            &blob_store,
        )
        .unwrap();
        let semantic = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let admitted = admit_semantic_git_import(&semantic, &blob_store).unwrap();

        assert!(admitted.changes.is_empty());
        assert!(admitted.commit_policies.is_empty());
        assert_eq!(
            admitted.workspace_policy(),
            &SharedAdmissionPolicy::empty(0)
        );
        assert_eq!(admitted.workspace_base_change_id(), None);
        admitted.validate(&blob_store).unwrap();
    }

    #[test]
    fn missing_tampered_cas_and_mutated_plan_fail_closed() {
        let root = tempdir().unwrap();
        let repo = root.path().join("source");
        fs::create_dir(&repo).unwrap();
        git_ok(&repo, ["init", "--initial-branch=main"]);
        configure_git(&repo);
        write(
            &repo,
            "compose.yaml",
            b"services:\n  api:\n    image: kin\n",
        );
        write(&repo, ".gitignore", b"*.scratch\n");
        git_ok(&repo, ["add", "--all"]);
        git_ok(&repo, ["commit", "-m", "initial"]);
        let cas_root = root.path().join("cas");
        let blob_store = BlobStore::new(cas_root.clone()).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repo,
            RepositoryId::new("semantic-cas").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let admitted = admit_semantic_git_import(&plan, &blob_store).unwrap();

        let mut mutated = plan.clone();
        mutated.changes[0].message.push_str("tampered");
        assert!(matches!(
            mutated.validate(&blob_store),
            Err(GitError::InvalidSnapshot(_))
        ));

        let ignore_hash = match plan
            .commit_trees
            .values()
            .next()
            .unwrap()
            .artifact_at_path(&repo_path(b".gitignore"))
            .unwrap()
            .entry
        {
            TreeEntry::Blob { hash, .. } => hash,
            other => panic!("unexpected .gitignore entry {other:?}"),
        };
        let mut mutated_admitted = admitted.clone();
        mutated_admitted.workspace_policy.generation += 1;
        assert!(matches!(
            mutated_admitted.validate(&blob_store),
            Err(GitError::InvalidSnapshot(_))
        ));

        let body = blob_store.read(&ignore_hash).unwrap();
        blob_store.delete(&ignore_hash).unwrap();
        assert!(matches!(
            admit_semantic_git_import(&plan, &blob_store),
            Err(GitError::Blob(kin_blobs::BlobError::NotFound { .. }))
        ));
        assert_eq!(blob_store.write(&body).unwrap(), ignore_hash);

        fs::write(cas_path(&cas_root, &ignore_hash), b"tampered").unwrap();
        assert!(matches!(
            admit_semantic_git_import(&plan, &blob_store),
            Err(GitError::Blob(kin_blobs::BlobError::HashMismatch { .. }))
        ));
    }

    #[cfg(unix)]
    fn change_for_oid(plan: &SemanticGitImportPlan, oid: GitObjectId) -> &SemanticChange {
        plan.changes
            .iter()
            .find(|change| change.origin == ChangeOrigin::GitCommit { oid })
            .unwrap()
    }

    #[cfg(unix)]
    fn alias_for_oid(plan: &SemanticGitImportPlan, oid: GitObjectId) -> &ExternalChangeAlias {
        plan.aliases.iter().find(|alias| alias.oid == oid).unwrap()
    }

    #[cfg(unix)]
    fn admitted_change_for_oid(
        plan: &AdmittedSemanticGitImportPlan,
        oid: GitObjectId,
    ) -> &SemanticChange {
        plan.changes
            .iter()
            .find(|change| change.origin == ChangeOrigin::GitCommit { oid })
            .unwrap()
    }

    #[cfg(unix)]
    fn admitted_alias_for_oid(
        plan: &AdmittedSemanticGitImportPlan,
        oid: GitObjectId,
    ) -> &ExternalChangeAlias {
        plan.aliases.iter().find(|alias| alias.oid == oid).unwrap()
    }

    #[cfg(unix)]
    fn artifact_id(tree: &ResolvedTree, path: &[u8]) -> ArtifactId {
        tree.artifact_at_path(&repo_path(path)).unwrap().artifact_id
    }

    #[cfg(unix)]
    fn assert_entry(tree: &ResolvedTree, path: &[u8], expected: TreeEntry) {
        let artifact = tree.artifact_at_path(&repo_path(path)).unwrap_or_else(|| {
            panic!(
                "missing semantic tree entry {}; available paths: {:?}",
                display_path(path),
                tree.artifacts_by_path()
                    .map(|artifact| display_path(artifact.path.as_bytes()))
                    .collect::<Vec<_>>()
            )
        });
        assert_eq!(
            artifact.entry,
            expected,
            "wrong semantic tree entry for {}",
            display_path(path)
        );
    }

    #[cfg(unix)]
    fn body_hash_for_blob(plan: &SemanticGitImportPlan, oid: GitObjectId) -> Hash256 {
        plan.external_objects
            .iter()
            .find(|record| record.object == ExternalObjectId::new(ExternalObjectKind::Blob, oid))
            .unwrap()
            .body_hash
    }

    fn repo_path(path: &[u8]) -> RepoPath {
        RepoPath::from_bytes(path).unwrap()
    }

    #[cfg(unix)]
    fn model_oid(hex_oid: &str) -> GitObjectId {
        let bytes = hex::decode(hex_oid).unwrap();
        match bytes.len() {
            20 => GitObjectId::sha1(bytes.try_into().unwrap()),
            32 => GitObjectId::sha256(bytes.try_into().unwrap()),
            length => panic!("unexpected Git object ID length {length}"),
        }
    }

    #[cfg(unix)]
    fn root_bundle() -> RootBundle {
        fn root(byte: u8) -> AuthorityRoot {
            AuthorityRoot::new(
                REPOSITORY_ROOT_SCHEMA_VERSION,
                Hash256::from_bytes([byte; 32]),
            )
        }

        RootBundle {
            version: REPOSITORY_ROOT_SCHEMA_VERSION,
            generation: 0,
            history: root(1),
            ref_state: root(2),
            ref_log: root(3),
            collaboration: root(4),
            replication: root(5),
            local_state: root(6),
        }
    }

    fn configure_git(repo: &Path) {
        git_ok(repo, ["config", "user.name", "Kin Test"]);
        git_ok(repo, ["config", "user.email", "kin@example.invalid"]);
        git_ok(repo, ["config", "commit.gpgsign", "false"]);
        git_ok(repo, ["config", "tag.gpgsign", "false"]);
        git_ok(repo, ["config", "core.autocrlf", "false"]);
        git_ok(repo, ["config", "core.filemode", "true"]);
    }

    fn write(repo: &Path, path: &str, body: &[u8]) {
        let path = repo.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn git_ok<I, S>(repo: &Path, args: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = git_output(repo, args);
        assert!(
            output.status.success(),
            "git failed ({}):\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    fn git_text<I, S>(repo: &Path, args: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = git_output(repo, args);
        assert!(
            output.status.success(),
            "git failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    #[cfg(unix)]
    fn git_stdin_ok<I, S>(repo: &Path, args: I, stdin: &[u8])
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = git_stdin_output(repo, args, stdin);
        assert!(
            output.status.success(),
            "git failed ({}):\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    fn git_stdin_text<I, S>(repo: &Path, args: I, stdin: &[u8]) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = git_stdin_output(repo, args, stdin);
        assert!(
            output.status.success(),
            "git failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn git_output<I, S>(repo: &Path, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        fixture_git().args(args).current_dir(repo).output().unwrap()
    }

    #[cfg(unix)]
    fn git_stdin_output<I, S>(repo: &Path, args: I, stdin: &[u8]) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        fixture_git()
            .args(args)
            .current_dir(repo)
            .output_with_input(stdin)
            .unwrap()
    }

    fn cas_path(root: &Path, hash: &Hash256) -> PathBuf {
        let hex = hash.to_string();
        root.join(&hex[..2]).join(&hex[2..])
    }
}
