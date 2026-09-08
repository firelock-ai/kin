// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Transaction-ready semantic import derived only from a validated lossless
//! Git snapshot and Kin's blob CAS.
//!
//! This module deliberately has no repository or filesystem input. Git is an
//! ingestion format at this boundary; raw object records remain available for
//! byte-exact projection, while semantic changes and resolved trees become the
//! graph-owned runtime authority.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use kin_blobs::BlobStore;
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, validate_semantic_change_id,
    ArtifactId, AuthorId, ChangeOrigin, DefaultRefExpectation, DefaultRefMutation, EntityDelta,
    ExternalChangeAlias, ExternalObjectId, ExternalObjectKind, ExternalObjectRecord, GitObjectId,
    Hash256, LocatedEntry, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
    RelationDelta, RepositoryId, RepositoryRefState, ResolvedTree, SemanticChange,
    SemanticChangeId, Timestamp, TreeDelta, TreeEntry, WorkspaceHead,
};
use uuid::Uuid;

use crate::error::{GitError, Result};
use crate::history_spool::{SemanticChangeSpool, SemanticChangeSpoolWriter};
use crate::lossless::{validate_snapshot, GitObjectFormat, LosslessGitRepository};
use crate::sealed_observation::{AdmittedContentSummary, SealedTreeObservation};

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

/// One imported change's historical semantics, owned or lent.
///
/// Streaming enrichment moves owned deltas into one change before it is
/// spooled. The compatibility binding API also accepts borrowed deltas from
/// callers that already hold a history.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalSemanticBinding<'a> {
    pub change_id: SemanticChangeId,
    pub entity_deltas: Cow<'a, [EntityDelta]>,
    pub relation_deltas: Cow<'a, [RelationDelta]>,
}

impl<'a> HistoricalSemanticBinding<'a> {
    /// Hand over deltas this caller will not read again.
    pub fn owned(
        change_id: SemanticChangeId,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
    ) -> Self {
        Self {
            change_id,
            entity_deltas: Cow::Owned(entity_deltas),
            relation_deltas: Cow::Owned(relation_deltas),
        }
    }

    /// Lend deltas that stay where they are.
    pub fn borrowed(
        change_id: SemanticChangeId,
        entity_deltas: &'a [EntityDelta],
        relation_deltas: &'a [RelationDelta],
    ) -> Self {
        Self {
            change_id,
            entity_deltas: Cow::Borrowed(entity_deltas),
            relation_deltas: Cow::Borrowed(relation_deltas),
        }
    }
}

/// Deterministic, transaction-ready import of one lossless Git snapshot.
///
/// `changes` are parent-first. `commit_tree_hashes` names the exact resolved
/// tree of every imported commit by its canonical hash, and `content` is what
/// the sealed all-content observation reads from those trees; neither holds a
/// tree. Ref mutations retain external-object targets so Git can be projected
/// byte-exactly after semantic admission.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticGitImportPlan {
    pub repository_id: RepositoryId,
    pub object_format: GitObjectFormat,
    pub external_objects: Vec<ExternalObjectRecord>,
    pub changes: SemanticChangeSpool,
    pub aliases: Vec<ExternalChangeAlias>,
    /// The canonical identity of every imported commit's exact tree, keyed by
    /// commit: thirty-two bytes where a conversion used to hold the tree
    /// itself, one per commit, for the whole of the ladder. The derivation
    /// resolves each tree against its first parent's, hands it to whoever
    /// needs it while it is live, and keeps this. A proof re-derives the tree
    /// and compares the hash, which is the equality `ResolvedTree` computes,
    /// because the hash is canonical over the tree's artifacts.
    pub commit_tree_hashes: BTreeMap<GitObjectId, Hash256>,
    /// What the sealed all-content observation needs from every commit tree,
    /// taken once while each tree was live: one digest and entry tally per
    /// commit, plus the distinct content identities, non-UTF-8 paths and
    /// declared exclusions the trees reference between them.
    pub content: AdmittedContentSummary,
    pub refs: RepositoryRefState,
    pub head: WorkspaceHead,
    pub workspace_seed: GitWorkspaceSeed,
    pub ref_mutations: Vec<RefMutation>,
    pub default_ref_mutation: Option<DefaultRefMutation>,
}

/// The plan fields every Git source proof reads.
///
/// Every proof in a conversion reads the same nine things out of an import
/// plan: the five raw-snapshot fields it must stay bound to, the change ids and
/// aliases and commit tree hashes its fingerprint covers, and the workspace
/// seed the index and worktree observations are taken against. None of them is
/// a change BODY. Naming that set as a trait is what lets one proof hold a
/// whole plan and the proofs after it hold only the closure, without the two
/// ever computing a fingerprint from different inputs.
pub trait ProvedPlanFacts {
    fn proved_repository_id(&self) -> &RepositoryId;
    fn proved_object_format(&self) -> GitObjectFormat;
    fn proved_external_objects(&self) -> &[ExternalObjectRecord];
    /// How many changes the plan carries, hashed before the ids themselves.
    fn proved_change_count(&self) -> usize;
    /// Change ids in the plan's own parent-first order.
    fn proved_change_ids(&self) -> impl Iterator<Item = SemanticChangeId> + '_;
    fn proved_aliases(&self) -> &[ExternalChangeAlias];
    fn proved_commit_tree_hashes(&self) -> &BTreeMap<GitObjectId, Hash256>;
    fn proved_refs(&self) -> &RepositoryRefState;
    fn proved_head(&self) -> &WorkspaceHead;
    fn proved_workspace_seed(&self) -> &GitWorkspaceSeed;
}

impl ProvedPlanFacts for SemanticGitImportPlan {
    fn proved_repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }
    fn proved_object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    fn proved_external_objects(&self) -> &[ExternalObjectRecord] {
        &self.external_objects
    }
    fn proved_change_count(&self) -> usize {
        self.changes.len()
    }
    fn proved_change_ids(&self) -> impl Iterator<Item = SemanticChangeId> + '_ {
        self.changes.ids()
    }
    fn proved_aliases(&self) -> &[ExternalChangeAlias] {
        &self.aliases
    }
    fn proved_commit_tree_hashes(&self) -> &BTreeMap<GitObjectId, Hash256> {
        &self.commit_tree_hashes
    }
    fn proved_refs(&self) -> &RepositoryRefState {
        &self.refs
    }
    fn proved_head(&self) -> &WorkspaceHead {
        &self.head
    }
    fn proved_workspace_seed(&self) -> &GitWorkspaceSeed {
        &self.workspace_seed
    }
}

/// What a conversion still needs from its import plan once the first source
/// proof has been taken.
///
/// A conversion holds its `SemanticGitImportPlan` from the phase that derives
/// it to the phase that seals the published repository, and after the first
/// proof nothing reads a change's body again. Every later reader was checked by
/// name: the plan fingerprint hashes each change's ID, the snapshot binding
/// reads the five raw-snapshot fields, the index and worktree observations read
/// the workspace seed, and the published seal reads the content summary and
/// the seed tree. What stays behind is `entity_deltas`, `relation_deltas` and
/// `tree_deltas` for every commit in history, live across the conversion's
/// peak, answering no question.
///
/// This is a type rather than a mutation on purpose. Emptying the plan's
/// vectors in place would leave a structure that still looks whole and would
/// answer a future reader with silence, which is the failure class this whole
/// area keeps producing. A closure that never carried the bodies cannot.
///
/// It is built by consuming the plan, so the bodies are freed at the call
/// rather than copied out beside them.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvedImportClosure {
    pub repository_id: RepositoryId,
    pub object_format: GitObjectFormat,
    pub external_objects: Vec<ExternalObjectRecord>,
    /// Change ids in the plan's parent-first order, which is every byte any
    /// proof after the first ever took from `changes`.
    pub change_ids: Vec<SemanticChangeId>,
    pub aliases: Vec<ExternalChangeAlias>,
    pub commit_tree_hashes: BTreeMap<GitObjectId, Hash256>,
    pub content: AdmittedContentSummary,
    pub refs: RepositoryRefState,
    pub head: WorkspaceHead,
    pub workspace_seed: GitWorkspaceSeed,
}

impl ProvedImportClosure {
    /// Take from a proved plan exactly what the proofs after it read.
    ///
    /// Consuming rather than borrowing is the point: the change bodies are
    /// dropped at this call instead of living on beside a copy of everything
    /// else.
    pub fn from_proved_plan(plan: SemanticGitImportPlan) -> Self {
        let change_ids = plan.changes.ids().collect();
        Self {
            repository_id: plan.repository_id,
            object_format: plan.object_format,
            external_objects: plan.external_objects,
            change_ids,
            aliases: plan.aliases,
            commit_tree_hashes: plan.commit_tree_hashes,
            content: plan.content,
            refs: plan.refs,
            head: plan.head,
            workspace_seed: plan.workspace_seed,
        }
    }
}

impl ProvedPlanFacts for ProvedImportClosure {
    fn proved_repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }
    fn proved_object_format(&self) -> GitObjectFormat {
        self.object_format
    }
    fn proved_external_objects(&self) -> &[ExternalObjectRecord] {
        &self.external_objects
    }
    fn proved_change_count(&self) -> usize {
        self.change_ids.len()
    }
    fn proved_change_ids(&self) -> impl Iterator<Item = SemanticChangeId> + '_ {
        self.change_ids.iter().copied()
    }
    fn proved_aliases(&self) -> &[ExternalChangeAlias] {
        &self.aliases
    }
    fn proved_commit_tree_hashes(&self) -> &BTreeMap<GitObjectId, Hash256> {
        &self.commit_tree_hashes
    }
    fn proved_refs(&self) -> &RepositoryRefState {
        &self.refs
    }
    fn proved_head(&self) -> &WorkspaceHead {
        &self.head
    }
    fn proved_workspace_seed(&self) -> &GitWorkspaceSeed {
        &self.workspace_seed
    }
}

impl SemanticGitImportPlan {
    /// This plan's own raw Git state, which every re-derivation starts from.
    fn raw_snapshot(&self) -> LosslessGitRepository {
        LosslessGitRepository {
            repository_id: self.repository_id.clone(),
            object_format: self.object_format,
            objects: self.external_objects.clone(),
            refs: self.refs.clone(),
            head: self.head.clone(),
        }
    }

    /// Rebuild the plan from its exact raw-object/ref state and require a
    /// byte-for-byte deterministic semantic result.
    ///
    /// The rebuild is compared commit by commit as it is derived, and each
    /// derived commit is dropped once it has been checked. That is the same
    /// comparison a whole-structure `!=` made, on the same bytes, in the same
    /// parent-first order; what it no longer does is hold a second complete
    /// history in order to check the first. No proof is weakened here and none
    /// is skipped: every commit's change, alias, and exact resolved tree is
    /// still re-derived from raw objects and still compared.
    pub fn validate(&self, blob_store: &BlobStore) -> Result<()> {
        let snapshot = self.raw_snapshot();
        let mut comparison = HeldPlanComparison::new(
            self,
            Enrichment::ReapplyHeldDeltas,
            DETERMINISTIC_DERIVATION,
        )?;
        let derived = derive_semantic_git_history(
            &snapshot,
            blob_store,
            TreeRetention::Frontier,
            &mut |oid, change, alias, _tree, facts| {
                comparison.check_commit(oid, change, alias, facts)
            },
        )?;
        comparison.finish(&derived)
    }

    /// Derive this plan's historical semantics from its own exact trees, one
    /// commit at a time, and bind them.
    ///
    /// The walk that re-derives the plan from raw objects to check it is the
    /// walk that hands each commit's live tree to `enrich`, so no whole-history
    /// map of trees is ever built to serve the fold: a tree exists for the
    /// commits that still resolve against it and is dropped after the last of
    /// them. `enrich` receives the held unenriched change the tree belongs to,
    /// in the plan's own parent-first order, and returns the deltas to bind to
    /// it. Everything [`Self::with_historical_semantics`] proves about a held
    /// plan and a set of bindings is proved here too, by the same comparison
    /// and the same re-identification.
    pub fn enrich_with_historical_semantics(
        self,
        blob_store: &BlobStore,
        enrich: &mut dyn FnMut(
            &SemanticChange,
            &ResolvedTree,
        ) -> Result<HistoricalSemanticBinding<'static>>,
    ) -> Result<Self> {
        enrich_with_historical_semantics(self, blob_store, enrich)
    }

    /// Bind deterministic CAS-native semantic deltas and recompute every
    /// change identity, parent edge, and external alias in parent-first order.
    pub fn with_historical_semantics(
        self,
        blob_store: &BlobStore,
        bindings: Vec<HistoricalSemanticBinding<'_>>,
    ) -> Result<Self> {
        let snapshot = LosslessGitRepository {
            repository_id: self.repository_id.clone(),
            object_format: self.object_format,
            objects: self.external_objects.clone(),
            refs: self.refs.clone(),
            head: self.head.clone(),
        };
        let mut comparison = HeldPlanComparison::new(&self, Enrichment::None, EXACT_UNENRICHED)?;
        let derived = derive_semantic_git_history(
            &snapshot,
            blob_store,
            TreeRetention::Frontier,
            &mut |oid, change, alias, _tree, facts| {
                comparison.check_commit(oid, change, alias, facts)
            },
        )?;
        comparison.finish(&derived)?;
        apply_historical_semantic_deltas_unchecked(self, blob_store, bindings)
    }
}

fn enrich_with_historical_semantics(
    plan: SemanticGitImportPlan,
    blob_store: &BlobStore,
    enrich: &mut dyn FnMut(
        &SemanticChange,
        &ResolvedTree,
    ) -> Result<HistoricalSemanticBinding<'static>>,
) -> Result<SemanticGitImportPlan> {
    let snapshot = plan.raw_snapshot();
    let mut comparison = HeldPlanComparison::new(&plan, Enrichment::None, EXACT_UNENRICHED)?;
    let mut changes = SemanticChangeSpoolWriter::new_in(blob_store.root())?;
    let mut aliases = Vec::with_capacity(plan.aliases.len());
    let mut old_to_new = BTreeMap::new();
    let derived = derive_semantic_git_history(
        &snapshot,
        blob_store,
        TreeRetention::Frontier,
        &mut |oid, change, alias, tree, facts| {
            comparison.check_commit(oid, change, alias, facts)?;
            let mut held = comparison.held_change(oid)?;
            let binding = enrich(&held, tree)?;
            if binding.change_id != held.id {
                return Err(GitError::InvalidSnapshot(
                    "historical semantic deltas name a different change".to_string(),
                ));
            }
            let old_id = held.id;
            held.parents = held
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
            held.entity_deltas = binding.entity_deltas.into_owned();
            held.relation_deltas = binding.relation_deltas.into_owned();
            held.id = placeholder_change_id();
            held.id = compute_semantic_change_id(&held)?;
            validate_semantic_change_id(&held)?;
            let alias = ExternalChangeAlias::new(plan.repository_id.clone(), oid, held.id);
            alias.validate_change(&held)?;
            old_to_new.insert(old_id, held.id);
            changes.append(held)?;
            aliases.push(alias);
            Ok(())
        },
    )?;
    comparison.finish(&derived)?;
    let mut plan = plan;
    plan.changes = changes.finish()?;
    plan.aliases = aliases;
    Ok(plan)
}

/// Build semantic Git history using only a lossless snapshot and its CAS.
pub fn plan_semantic_git_import(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
) -> Result<SemanticGitImportPlan> {
    build_semantic_git_import_plan(snapshot, blob_store)
}

/// What an enriched re-derivation still holds once every commit has been
/// visited and dropped.
///
/// Deliberately not [`DerivedGitHistory`]: that carries the trees the walk had
/// not finished with, and a caller checking history it already holds has no
/// reader for them, so they are dropped here rather than handed back.
pub(crate) struct DerivedEnrichedHistory {
    pub(crate) workspace_seed: GitWorkspaceSeed,
    pub(crate) ref_mutations: Vec<RefMutation>,
    pub(crate) default_ref_mutation: Option<DefaultRefMutation>,
    /// Every commit's tree by canonical hash, for a caller to compare whole.
    pub(crate) commit_tree_hashes: BTreeMap<GitObjectId, Hash256>,
    /// Every commit tree's contribution to the sealed observation.
    pub(crate) content: AdmittedContentSummary,
    /// Commits derived, which a caller compares against what it holds.
    pub(crate) commits: usize,
}

/// Re-derive exact semantic history from a lossless snapshot and re-apply the
/// historical semantics the caller already holds, handing every commit to
/// `visit` in parent-first order with its parents' object ids and its exact
/// resolved tree.
///
/// This is [`SemanticGitImportPlan::validate`]'s walk with the enrichment
/// [`SemanticGitImportPlan::with_historical_semantics`] performs folded into
/// it. A caller that already holds the enriched history can therefore check it
/// commit by commit rather than build a second complete history to compare
/// against, which is what made re-proving a plan cost about as much as deriving
/// one. Only the visitor decides what survives the commit it was handed; this
/// walk keeps the frontier trees the derivation itself needs, plus one identity
/// pair per commit, and nothing else.
pub(crate) fn derive_enriched_semantic_git_history(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
    held_semantics: &dyn Fn(GitObjectId) -> Result<Option<(Vec<EntityDelta>, Vec<RelationDelta>)>>,
    visit: &mut dyn FnMut(
        GitObjectId,
        &[GitObjectId],
        SemanticChange,
        ExternalChangeAlias,
        &ResolvedTree,
        &CommitTreeFacts,
    ) -> Result<()>,
) -> Result<DerivedEnrichedHistory> {
    // Pre-enrichment identity to (object id, enriched identity). A derived
    // change names its parents by the identity the unenriched walk computed,
    // and re-applying held deltas changes every identity, so the walk carries
    // that mapping rather than a second history. Parent-first order is what
    // makes one pass enough.
    let mut resolved = BTreeMap::<SemanticChangeId, (GitObjectId, SemanticChangeId)>::new();
    let derived = derive_semantic_git_history(
        snapshot,
        blob_store,
        TreeRetention::Frontier,
        &mut |oid, mut change, _unenriched_alias, tree, facts| {
            let unenriched_id = change.id;
            let mut parent_oids = Vec::with_capacity(change.parents.len());
            let mut parents = Vec::with_capacity(change.parents.len());
            for parent in &change.parents {
                let (parent_oid, parent_id) = resolved.get(parent).copied().ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "parent {parent} was not reidentified before change {unenriched_id}"
                    ))
                })?;
                parent_oids.push(parent_oid);
                parents.push(parent_id);
            }
            let Some((entity_deltas, relation_deltas)) = held_semantics(oid)? else {
                return Err(GitError::InvalidSnapshot(format!(
                    "historical semantic deltas omit Git commit {oid}"
                )));
            };
            change.parents = parents;
            change.entity_deltas = entity_deltas;
            change.relation_deltas = relation_deltas;
            change.id = placeholder_change_id();
            change.id = compute_semantic_change_id(&change)?;
            validate_semantic_change_id(&change)?;
            let alias = ExternalChangeAlias::new(snapshot.repository_id.clone(), oid, change.id);
            alias.validate_change(&change)?;
            if resolved.insert(unenriched_id, (oid, change.id)).is_some() {
                return Err(GitError::InvalidSnapshot(format!(
                    "pre-enrichment semantic identity {unenriched_id} maps to more than one Git commit"
                )));
            }
            visit(oid, &parent_oids, change, alias, tree, facts)
        },
    )?;
    Ok(DerivedEnrichedHistory {
        workspace_seed: derived.workspace_seed,
        ref_mutations: derived.ref_mutations,
        default_ref_mutation: derived.default_ref_mutation,
        commit_tree_hashes: derived.commit_tree_hashes,
        content: derived.content,
        commits: derived.commits,
    })
}

fn apply_historical_semantic_deltas_unchecked(
    mut plan: SemanticGitImportPlan,
    blob_store: &BlobStore,
    bindings: Vec<HistoricalSemanticBinding<'_>>,
) -> Result<SemanticGitImportPlan> {
    let mut delta_by_change = BTreeMap::new();
    for binding in bindings {
        let change_id = binding.change_id;
        if delta_by_change
            .insert(change_id, (binding.entity_deltas, binding.relation_deltas))
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
    let mut changes = SemanticChangeSpoolWriter::new_in(blob_store.root())?;
    let mut aliases = Vec::with_capacity(plan.changes.len());
    for change in plan.changes.iter() {
        let mut change = change?;
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
        // `into_owned` is a move for an owned binding and a copy for a lent
        // one, so each caller pays exactly once for the copy it cannot avoid
        // and nothing pays twice.
        //
        // Shrunk because moving preserves capacity where copying did not. A
        // derived vector was grown by pushing, so it carries whatever slack the
        // doubling left, and these vectors are retained for the rest of the
        // conversion. Measured on psf/requests at 6731 commits, that slack was
        // 108.1 MiB, and it is live from here to the last phase, so taking the
        // move without this made the whole conversion's peak WORSE by exactly
        // that much while the phase's own peak fell by 1081.4 MiB.
        change.entity_deltas = delta.0.into_owned();
        change.entity_deltas.shrink_to_fit();
        change.relation_deltas = delta.1.into_owned();
        change.relation_deltas.shrink_to_fit();
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
        changes.append(change)?;
        aliases.push(alias);
    }
    if !delta_by_change.is_empty() {
        return Err(GitError::InvalidSnapshot(
            "historical semantic deltas contain unknown changes".to_string(),
        ));
    }
    plan.changes = changes.finish()?;
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

/// Refusal when a plan does not match what its own raw objects derive.
const DETERMINISTIC_DERIVATION: &str =
    "semantic Git import plan does not match its deterministic raw-object derivation";

/// Refusal when historical semantics are offered against something other than
/// the exact unenriched plan.
const EXACT_UNENRICHED: &str =
    "historical semantics may only be bound to the exact unenriched import plan";

/// Whether the plan a re-derivation is checked against already carries bound
/// semantics.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Enrichment {
    /// The held plan is the exact unenriched derivation, so each derived commit
    /// is compared as it comes off the walk.
    None,
    /// The held plan carries bound entity and relation deltas. Each derived
    /// commit has the held commit's own deltas re-applied to it first, and the
    /// identity that re-application computes is what gets compared, which is
    /// exactly what rebuilding the whole enriched plan used to do.
    ReapplyHeldDeltas,
}

/// Checks a re-derivation against a held plan one commit at a time.
///
/// This replaces a whole-structure `rebuilt != *self`. It compares the same
/// values, derived the same way, in the same parent-first order, and refuses
/// with the same sentence. The difference is that a commit is compared the
/// instant it is derived and dropped immediately after, so proving a history
/// no longer costs a second copy of it.
struct HeldPlanComparison<'a> {
    plan: &'a SemanticGitImportPlan,
    enrichment: Enrichment,
    refusal: &'static str,
    /// Where each Git commit's held change sits, so a derived commit can find
    /// the deltas to re-apply without a whole-history copy of them.
    held_by_oid: BTreeMap<GitObjectId, usize>,
    /// Pre-admission identity to the identity re-application computes, which is
    /// how a re-applied change reaches its parents. Identities only, so this
    /// stays small no matter how deep history is.
    reidentified: BTreeMap<SemanticChangeId, SemanticChangeId>,
    checked: usize,
}

impl<'a> HeldPlanComparison<'a> {
    fn new(
        plan: &'a SemanticGitImportPlan,
        enrichment: Enrichment,
        refusal: &'static str,
    ) -> Result<Self> {
        let mut held_by_oid = BTreeMap::new();
        for (index, change) in plan.changes.iter().enumerate() {
            let change = change?;
            let ChangeOrigin::GitCommit { oid } = change.origin else {
                return Err(GitError::InvalidSnapshot(
                    "semantic Git import contains a native-origin change".to_string(),
                ));
            };
            if held_by_oid.insert(oid, index).is_some() {
                return Err(GitError::InvalidSnapshot(format!(
                    "semantic Git import repeats commit {oid}"
                )));
            }
        }
        Ok(Self {
            plan,
            enrichment,
            refusal,
            held_by_oid,
            reidentified: BTreeMap::new(),
            checked: 0,
        })
    }

    fn refuse(&self) -> GitError {
        GitError::InvalidSnapshot(self.refusal.to_string())
    }

    /// The held change for one Git commit, wherever it sits in the plan.
    fn held_change(&self, oid: GitObjectId) -> Result<SemanticChange> {
        let index = *self.held_by_oid.get(&oid).ok_or_else(|| {
            GitError::InvalidSnapshot(format!(
                "semantic Git import is missing enriched commit {oid}"
            ))
        })?;
        self.plan
            .changes
            .read_at(index)?
            .ok_or_else(|| self.refuse())
    }

    fn check_commit(
        &mut self,
        oid: GitObjectId,
        mut change: SemanticChange,
        alias: ExternalChangeAlias,
        facts: &CommitTreeFacts,
    ) -> Result<()> {
        let held_index = *self.held_by_oid.get(&oid).ok_or_else(|| {
            GitError::InvalidSnapshot(format!(
                "semantic Git import is missing enriched commit {oid}"
            ))
        })?;
        let mut alias = alias;
        if self.enrichment == Enrichment::ReapplyHeldDeltas {
            let held = self
                .plan
                .changes
                .read_at(held_index)?
                .ok_or_else(|| self.refuse())?;
            let old_id = change.id;
            change.parents = change
                .parents
                .iter()
                .map(|parent| {
                    self.reidentified.get(parent).copied().ok_or_else(|| {
                        GitError::InvalidSnapshot(format!(
                            "parent {parent} was not reidentified before change {old_id}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            change.entity_deltas = held.entity_deltas;
            change.relation_deltas = held.relation_deltas;
            change.id = placeholder_change_id();
            change.id = compute_semantic_change_id(&change)?;
            validate_semantic_change_id(&change)?;
            alias = ExternalChangeAlias::new(self.plan.repository_id.clone(), oid, change.id);
            alias.validate_change(&change)?;
            self.reidentified.insert(old_id, change.id);
        }

        // Positional, because whole-`Vec` equality asserted order as well as
        // content. The held commit is located by object id for its deltas and
        // compared at the position the derivation reached, so a plan whose
        // changes are reordered still fails here.
        // The tree is compared by its canonical hash and by what the seal
        // will read from it, both computed fresh by this derivation, so a
        // held plan whose tree hash or content summary was altered fails at
        // the commit it was altered for.
        let index = self.checked;
        if self.plan.changes.read_at(index)?.as_ref() != Some(&change)
            || self.plan.aliases.get(index) != Some(&alias)
            || self.plan.commit_tree_hashes.get(&oid) != Some(&facts.tree_hash)
            || self.plan.content.trees.get(&oid) != Some(&facts.content)
        {
            return Err(self.refuse());
        }
        self.checked += 1;
        Ok(())
    }

    fn finish(self, derived: &DerivedGitHistory) -> Result<()> {
        // Every derived commit matched a held one at its own position, and the
        // derivation already refused unless it derived each reachable commit
        // exactly once. Requiring the held collections to be exactly that long
        // is what rules out a plan carrying anything extra, which is the other
        // half of what whole-structure equality asserted.
        if self.checked != derived.commits
            || self.plan.changes.len() != derived.commits
            || self.plan.aliases.len() != derived.commits
            || self.plan.commit_tree_hashes.len() != derived.commits
            || self.plan.content != derived.content
            || self.plan.workspace_seed != derived.workspace_seed
            || self.plan.ref_mutations != derived.ref_mutations
            || self.plan.default_ref_mutation != derived.default_ref_mutation
        {
            return Err(self.refuse());
        }
        Ok(())
    }
}

/// What a history derivation keeps while it walks parent-first.
///
/// An exact `ResolvedTree` is the widest structure the walk touches, one map
/// over every artifact in the repository, and holding one per commit is what
/// made a conversion's peak follow commits multiplied by files. Nothing in the
/// product reads a whole-history map of them any more: every reader takes its
/// tree from the walk while the tree is live, so the product walks under
/// [`Self::Frontier`] and only a test asks for [`Self::Whole`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TreeRetention {
    /// Keep every commit's exact tree, for a test that wants to look at one
    /// after the walk.
    #[cfg(any(test, feature = "test-support"))]
    Whole,
    /// Keep only the trees a later commit still resolves against, plus the one
    /// the workspace seed peels to.
    ///
    /// A structural revalidation compares each commit the instant it is derived
    /// and never reads that commit's tree again once its last child is
    /// resolved. Holding the rest means holding a second whole history in order
    /// to prove the first, which is what made a re-derivation cost as much as
    /// the derivation it checks.
    Frontier,
}

/// What a derivation computes from one commit's exact tree while the tree is
/// live, and a plan keeps in the tree's place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitTreeFacts {
    /// The tree's canonical identity, `compute_resolved_tree_hash`.
    pub tree_hash: Hash256,
    /// What the sealed all-content observation reads from the tree.
    pub content: SealedTreeObservation,
}

/// What a derivation still holds once every commit has been visited.
struct DerivedGitHistory {
    /// Every commit's exact tree, for a test that walked under
    /// [`TreeRetention::Whole`]. The product never reads a tree out of a
    /// finished derivation, so the field exists only where the test helper
    /// that returns it does.
    #[cfg(any(test, feature = "test-support"))]
    commit_trees: BTreeMap<GitObjectId, ResolvedTree>,
    /// Every commit's tree by canonical hash, whatever the retention.
    commit_tree_hashes: BTreeMap<GitObjectId, Hash256>,
    /// Every commit tree's contribution to the sealed observation.
    content: AdmittedContentSummary,
    workspace_seed: GitWorkspaceSeed,
    ref_mutations: Vec<RefMutation>,
    default_ref_mutation: Option<DefaultRefMutation>,
    /// Commits derived, which a caller compares against what it accumulated.
    commits: usize,
}

/// Derive exact semantic history from a lossless snapshot and its CAS, handing
/// every commit to `visit` in parent-first order as it is resolved.
///
/// This is the single derivation rule. Building a plan and re-deriving one to
/// check it against are the same walk with different visitors, so the two can
/// never drift apart, and only the visitor decides what survives the commit it
/// was handed. Each commit's tree is resolved from its first parent's and the
/// leaves that differ between the two Git tree objects, so the walk's work per
/// commit follows what the commit changed, and its memory follows the trees
/// still being resolved against rather than the length of history.
fn derive_semantic_git_history(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
    retention: TreeRetention,
    visit: &mut dyn FnMut(
        GitObjectId,
        SemanticChange,
        ExternalChangeAlias,
        &ResolvedTree,
        &CommitTreeFacts,
    ) -> Result<()>,
) -> Result<DerivedGitHistory> {
    let bodies = validate_snapshot(snapshot, blob_store)?;
    let records = snapshot
        .objects
        .iter()
        .map(|record| (record.object, record))
        .collect::<BTreeMap<_, _>>();
    let hash_kind = gix_hash_kind(snapshot.object_format);
    let commits = parse_commits(snapshot, &bodies, hash_kind)?;
    let order = topological_commit_order(&commits)?;

    let tree_decoder = TreeDecoder::new(hash_kind, &bodies, &records);

    // A commit's exact tree has exactly two kinds of reader: the commits that
    // name it as a parent, and the workspace seed. Counting them before the
    // walk is what lets a bounded derivation drop a tree the moment its last
    // reader is done, rather than at the end of history.
    let mut remaining_readers = BTreeMap::<GitObjectId, usize>::new();
    for parsed in commits.values() {
        for parent in &parsed.parents {
            *remaining_readers.entry(*parent).or_default() += 1;
        }
    }
    let seed_commit = resolve_workspace_seed_commit(snapshot, &bodies, hash_kind)?;
    if let Some(seed) = seed_commit {
        *remaining_readers.entry(seed).or_default() += 1;
    }

    let mut commit_trees = BTreeMap::new();
    let mut commit_tree_hashes = BTreeMap::new();
    let mut content = AdmittedContentSummary::default();
    let mut change_ids = BTreeMap::new();
    let mut known_artifact_ids = BTreeSet::new();
    let unborn_tree = ResolvedTree::default();
    let mut derived = 0usize;

    for oid in order {
        let parsed = commits.get(&oid).ok_or_else(|| {
            GitError::InvalidSnapshot(format!("topological order contains unknown commit {oid}"))
        })?;
        let first_parent_tree = match parsed.parents.first() {
            Some(parent) => commit_trees.get(parent).ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "first parent {parent} was not resolved before commit {oid}"
                ))
            })?,
            None => &unborn_tree,
        };
        let first_parent_root = parsed
            .parents
            .first()
            .map(|parent| {
                commits
                    .get(parent)
                    .map(|parsed| parsed.tree)
                    .ok_or_else(|| {
                        GitError::InvalidSnapshot(format!(
                            "first parent {parent} was not parsed before commit {oid}"
                        ))
                    })
            })
            .transpose()?;
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
        let raw_changes = tree_decoder.diff_trees(first_parent_root, parsed.tree)?;
        let (tree_deltas, resolved_tree) = resolve_tree_transition(
            oid,
            first_parent_tree,
            &secondary_parent_trees,
            raw_changes,
            &known_artifact_ids,
        )?;
        // Only an added path brings a new identity into history; every other
        // identity in this tree was known when the tree it was carried from
        // was derived.
        known_artifact_ids.extend(tree_deltas.iter().filter_map(|delta| {
            matches!(delta, TreeDelta::Added { .. }).then(|| delta.artifact_id())
        }));

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

        let facts = CommitTreeFacts {
            tree_hash: compute_resolved_tree_hash(&resolved_tree)?,
            content: content.observe_commit_tree(oid, &resolved_tree)?,
        };
        commit_tree_hashes.insert(oid, facts.tree_hash);
        change_ids.insert(oid, change.id);
        visit(oid, change, alias, &resolved_tree, &facts)?;
        commit_trees.insert(oid, resolved_tree);
        derived += 1;

        if retention == TreeRetention::Frontier {
            let parents = commits
                .get(&oid)
                .map(|parsed| parsed.parents.clone())
                .unwrap_or_default();
            for parent in &parents {
                let Some(remaining) = remaining_readers.get_mut(parent) else {
                    continue;
                };
                *remaining = remaining.checked_sub(1).ok_or_else(|| {
                    GitError::InvalidSnapshot(format!(
                        "parent {parent} of commit {oid} has invalid tree-reader accounting"
                    ))
                })?;
                if *remaining == 0 {
                    commit_trees.remove(parent);
                }
            }
            // A ref tip that nothing else reads, and that is not the seed, is
            // finished the moment it is derived.
            if remaining_readers.get(&oid).copied().unwrap_or(0) == 0 {
                commit_trees.remove(&oid);
            }
        }
    }

    if derived != commits.len() {
        return Err(GitError::InvalidSnapshot(
            "not every reachable Git commit was derived exactly once".to_string(),
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

    Ok(DerivedGitHistory {
        #[cfg(any(test, feature = "test-support"))]
        commit_trees,
        commit_tree_hashes,
        content,
        workspace_seed,
        ref_mutations,
        default_ref_mutation,
        commits: commits.len(),
    })
}

/// Every commit's exact resolved tree, derived whole, for a test that wants to
/// look at one after the walk.
///
/// The product never asks for this: a conversion holds a tree only while a
/// later commit still resolves against it. This exists so a test can pin what
/// a commit's tree contains without the plan carrying every tree for it.
#[cfg(any(test, feature = "test-support"))]
pub fn derive_commit_trees(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
) -> Result<BTreeMap<GitObjectId, ResolvedTree>> {
    let derived = derive_semantic_git_history(
        snapshot,
        blob_store,
        TreeRetention::Whole,
        &mut |_oid, _change, _alias, _tree, _facts| Ok(()),
    )?;
    Ok(derived.commit_trees)
}

fn build_semantic_git_import_plan(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
) -> Result<SemanticGitImportPlan> {
    let mut changes = SemanticChangeSpoolWriter::new_in(blob_store.root())?;
    let mut aliases = Vec::new();
    let derived = derive_semantic_git_history(
        snapshot,
        blob_store,
        TreeRetention::Frontier,
        &mut |_oid, change, alias, _tree, _facts| {
            changes.append(change)?;
            aliases.push(alias);
            Ok(())
        },
    )?;

    if derived.commit_tree_hashes.len() != derived.commits
        || derived.content.trees.len() != derived.commits
        || changes.len() != derived.commits
        || aliases.len() != derived.commits
    {
        return Err(GitError::InvalidSnapshot(
            "not every reachable Git commit produced one tree, change, and alias".to_string(),
        ));
    }

    Ok(SemanticGitImportPlan {
        repository_id: snapshot.repository_id.clone(),
        object_format: snapshot.object_format,
        external_objects: snapshot.objects.clone(),
        changes: changes.finish()?,
        aliases,
        commit_tree_hashes: derived.commit_tree_hashes,
        content: derived.content,
        refs: snapshot.refs.clone(),
        head: snapshot.head.clone(),
        workspace_seed: derived.workspace_seed,
        ref_mutations: derived.ref_mutations,
        default_ref_mutation: derived.default_ref_mutation,
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

/// Decodes tree objects out of the verified closure, one directory at a time.
///
/// It reads a tree object's DIRECT entries, nothing beneath them, and it
/// caches nothing. The decoder this replaces flattened every tree object in
/// the closure into a map of every leaf under it and cached each map, so a
/// repository's root tree, distinct in nearly every commit, was held once per
/// commit with every file in it: commits times files, before the resolved
/// trees were counted at all. A commit is resolved here by comparing its root
/// tree object with its first parent's and descending only where the two
/// differ, so the work per commit follows what the commit changed rather than
/// what the repository holds.
struct TreeDecoder<'a> {
    hash_kind: gix::hash::Kind,
    bodies: &'a BTreeMap<ExternalObjectId, Vec<u8>>,
    records: &'a BTreeMap<ExternalObjectId, &'a ExternalObjectRecord>,
}

/// One direct entry of a decoded tree object.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RawTreeEntry {
    /// A subdirectory, named by its tree object.
    Tree(GitObjectId),
    /// A leaf, already resolved to the identity Kin records for it.
    Leaf(TreeEntry),
}

/// One leaf that differs between a commit's tree and its first parent's.
struct RawPathChange {
    path: kin_model::RepoPath,
    old: Option<TreeEntry>,
    new: Option<TreeEntry>,
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
        }
    }

    /// The direct entries of one tree object, keyed by name.
    fn direct_entries(&self, tree_oid: GitObjectId) -> Result<BTreeMap<Vec<u8>, RawTreeEntry>> {
        let object = ExternalObjectId::new(ExternalObjectKind::Tree, tree_oid);
        let body = self
            .bodies
            .get(&object)
            .ok_or_else(|| GitError::MissingObject {
                oid: tree_oid.to_string(),
                context: "semantic tree decoding".to_string(),
            })?;
        let tree = gix::objs::TreeRef::from_bytes(body, self.hash_kind).map_err(|error| {
            GitError::InvalidSnapshot(format!("decode tree {tree_oid}: {error}"))
        })?;
        let mut entries = BTreeMap::new();
        for entry in tree.entries {
            let entry_oid = git_object_id(entry.oid.to_owned())?;
            let resolved = match entry.mode.kind() {
                gix::objs::tree::EntryKind::Tree => RawTreeEntry::Tree(entry_oid),
                gix::objs::tree::EntryKind::Blob => {
                    RawTreeEntry::Leaf(self.blob_entry(entry_oid, false)?)
                }
                gix::objs::tree::EntryKind::BlobExecutable => {
                    RawTreeEntry::Leaf(self.blob_entry(entry_oid, true)?)
                }
                gix::objs::tree::EntryKind::Link => {
                    RawTreeEntry::Leaf(TreeEntry::symlink(self.blob_record(entry_oid)?.body_hash))
                }
                gix::objs::tree::EntryKind::Commit if entry.mode.value() == 0o160000 => {
                    RawTreeEntry::Leaf(TreeEntry::gitlink(entry_oid))
                }
                gix::objs::tree::EntryKind::Commit => {
                    return Err(GitError::InvalidSnapshot(format!(
                        "tree {tree_oid} contains unsupported mode {:#o}",
                        entry.mode.value()
                    )));
                }
            };
            if entries.insert(entry.filename.to_vec(), resolved).is_some() {
                return Err(GitError::InvalidSnapshot(format!(
                    "tree {tree_oid} repeats path {}",
                    display_path(entry.filename)
                )));
            }
        }
        Ok(entries)
    }

    /// Every leaf that differs between `base` and `target`, in path order.
    ///
    /// `None` for `base` is the empty tree a root commit descends from. Two
    /// subtrees named by the same object are identical to the byte, so the walk
    /// never opens them, which is what makes a commit cost what it touched.
    fn diff_trees(
        &self,
        base: Option<GitObjectId>,
        target: GitObjectId,
    ) -> Result<Vec<RawPathChange>> {
        let mut changes = Vec::new();
        self.diff_into(base, Some(target), &mut Vec::new(), &mut changes)?;
        changes.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        Ok(changes)
    }

    fn diff_into(
        &self,
        base: Option<GitObjectId>,
        target: Option<GitObjectId>,
        prefix: &mut Vec<u8>,
        changes: &mut Vec<RawPathChange>,
    ) -> Result<()> {
        if base == target {
            return Ok(());
        }
        let base_entries = base
            .map(|oid| self.direct_entries(oid))
            .transpose()?
            .unwrap_or_default();
        let target_entries = target
            .map(|oid| self.direct_entries(oid))
            .transpose()?
            .unwrap_or_default();
        let names = base_entries
            .keys()
            .chain(target_entries.keys())
            .map(Vec::as_slice)
            .collect::<BTreeSet<_>>();
        for name in names {
            let old = base_entries.get(name).copied();
            let new = target_entries.get(name).copied();
            if old == new {
                continue;
            }
            let mark = prefix.len();
            if !prefix.is_empty() {
                prefix.push(b'/');
            }
            prefix.extend_from_slice(name);
            let (old_leaf, old_tree) = split_raw_entry(old);
            let (new_leaf, new_tree) = split_raw_entry(new);
            // A side that is a directory contributes every leaf beneath it,
            // and a side that is a leaf contributes itself at this path. A
            // path that changes shape between the two, a file replaced by a
            // directory or the reverse, therefore yields both.
            if old_tree.is_some() || new_tree.is_some() {
                self.diff_into(old_tree, new_tree, prefix, changes)?;
            }
            if old_leaf.is_some() || new_leaf.is_some() {
                let path = kin_model::RepoPath::from_bytes(prefix.clone()).map_err(|error| {
                    GitError::InvalidSnapshot(format!(
                        "invalid path {} in tree: {error}",
                        display_path(prefix)
                    ))
                })?;
                changes.push(RawPathChange {
                    path,
                    old: old_leaf,
                    new: new_leaf,
                });
            }
            prefix.truncate(mark);
        }
        Ok(())
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

fn split_raw_entry(entry: Option<RawTreeEntry>) -> (Option<TreeEntry>, Option<GitObjectId>) {
    match entry {
        Some(RawTreeEntry::Leaf(leaf)) => (Some(leaf), None),
        Some(RawTreeEntry::Tree(tree)) => (None, Some(tree)),
        None => (None, None),
    }
}

/// Resolve a commit's exact tree from its first parent's and the leaves that
/// differ, carrying artifact identity across the transition.
///
/// The identity rule is the one the whole-tree resolution applied, unchanged,
/// so a repository admitted before this derivation and one admitted after it
/// derive the same artifact identities, the same tree deltas and the same
/// change identities: a path the first parent carries keeps that parent's
/// identity whatever happens to its entry; a path it does not carry takes the
/// identity of the one artifact in a secondary parent with exactly the same
/// entry, when that match is unique in both directions and the first parent
/// does not still hold it; and every other new path is introduced under an
/// identity derived from this commit and the path.
///
/// The deltas are sorted by artifact identity, as before, and the tree is
/// built by applying them to the first parent's, which is the transition the
/// whole-tree resolution checked its result against. Building the tree that
/// way makes the check the construction.
fn resolve_tree_transition(
    introducing_commit: GitObjectId,
    first_parent: &ResolvedTree,
    secondary_parents: &[&ResolvedTree],
    changes: Vec<RawPathChange>,
    known_artifact_ids: &BTreeSet<ArtifactId>,
) -> Result<(Vec<TreeDelta>, ResolvedTree)> {
    let first_parent_id = |path: &kin_model::RepoPath| {
        first_parent
            .artifact_at_path(path)
            .map(|artifact| artifact.artifact_id)
            .ok_or_else(|| {
                GitError::InvalidSnapshot(format!(
                    "commit {introducing_commit} changes {path}, which its first parent's tree \
                     does not carry"
                ))
            })
    };

    let mut addition_counts = HashMap::<TreeEntry, usize>::new();
    // The first parent's side of every path this commit removes, by identity.
    // Held apart from the deltas because a removed identity can be claimed
    // back by an added path below, and then the two are one transition.
    let mut removed = BTreeMap::<ArtifactId, LocatedEntry>::new();
    for change in &changes {
        match (change.old, change.new) {
            (None, Some(entry)) => *addition_counts.entry(entry).or_default() += 1,
            (Some(old), None) => {
                let artifact_id = first_parent_id(&change.path)?;
                if removed
                    .insert(artifact_id, LocatedEntry::new(change.path.clone(), old))
                    .is_some()
                {
                    return Err(GitError::InvalidSnapshot(format!(
                        "commit {introducing_commit} removes artifact {artifact_id:?} at more than \
                         one path"
                    )));
                }
            }
            _ => {}
        }
    }

    // Only a merge can carry an identity in from a secondary parent, and only
    // an added path can receive one, so the candidate table is built only when
    // both exist. It is the one place this resolution still reads a whole
    // parent tree, once per secondary parent of a merge that adds a path.
    let mut secondary_candidates = HashMap::<TreeEntry, BTreeSet<ArtifactId>>::new();
    let mut candidate_target_counts = BTreeMap::<ArtifactId, usize>::new();
    if !addition_counts.is_empty() && !secondary_parents.is_empty() {
        for parent in secondary_parents {
            for artifact in parent.artifacts() {
                secondary_candidates
                    .entry(artifact.entry)
                    .or_default()
                    .insert(artifact.artifact_id);
            }
        }
        for change in &changes {
            let (None, Some(entry)) = (change.old, change.new) else {
                continue;
            };
            if let Some(candidates) = secondary_candidates.get(&entry) {
                for candidate in candidates {
                    *candidate_target_counts.entry(*candidate).or_default() += 1;
                }
            }
        }
    }
    let mut assigned = BTreeSet::new();
    let mut deltas = Vec::with_capacity(changes.len());
    for change in changes {
        let RawPathChange { path, old, new } = change;
        match (old, new) {
            (Some(old), Some(new)) => {
                let artifact_id = first_parent_id(&path)?;
                deltas.push(TreeDelta::Updated {
                    artifact_id,
                    old: LocatedEntry::new(path.clone(), old),
                    new: LocatedEntry::new(path, new),
                });
            }
            // Recorded in `removed` above; emitted below, unless an added
            // path claims the identity back first.
            (Some(_), None) => {}
            (None, Some(new)) => {
                let candidate = (addition_counts.get(&new) == Some(&1))
                    .then(|| secondary_candidates.get(&new))
                    .flatten()
                    .filter(|candidates| candidates.len() == 1)
                    .and_then(|candidates| candidates.first().copied())
                    .filter(|candidate| {
                        // An identity the first parent still holds at a path
                        // this commit keeps is reserved for it.
                        let reserved = first_parent.get(candidate).is_some()
                            && !removed.contains_key(candidate);
                        candidate_target_counts.get(candidate) == Some(&1)
                            && !reserved
                            && !assigned.contains(candidate)
                    });
                let artifact_id = match candidate {
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
                };
                if !assigned.insert(artifact_id) {
                    return Err(GitError::InvalidSnapshot(format!(
                        "artifact identity {artifact_id:?} is assigned to more than one path in commit {introducing_commit}"
                    )));
                }
                // A candidate the first parent held at a path this commit
                // removes is one artifact that moved, which the whole-tree diff
                // reported as a single update from the old path to the new,
                // never as a removal and an addition of the same identity,
                // which `ResolvedTree::apply` refuses as a duplicate.
                match removed.remove(&artifact_id) {
                    Some(old) => deltas.push(TreeDelta::Updated {
                        artifact_id,
                        old,
                        new: LocatedEntry::new(path, new),
                    }),
                    None => deltas.push(TreeDelta::Added {
                        artifact_id,
                        new: LocatedEntry::new(path, new),
                    }),
                }
            }
            (None, None) => {
                return Err(GitError::InvalidSnapshot(format!(
                    "commit {introducing_commit} reports a change at {path} with no side"
                )));
            }
        }
    }
    for (artifact_id, old) in removed {
        deltas.push(TreeDelta::Removed { artifact_id, old });
    }
    deltas.sort_by_key(TreeDelta::artifact_id);

    let resolved = first_parent.apply(&deltas).map_err(|error| {
        GitError::InvalidSnapshot(format!(
            "commit {introducing_commit} has an invalid first-parent tree transition: {error}"
        ))
    })?;
    Ok((deltas, resolved))
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
/// This runs only for a path the parent tree has no identity for. Continuity
/// across a commit comes from reusing the first parent's id, and across a merge
/// from the secondary-candidate matching above; neither is changed here. So the
/// commit in the key is the commit that *introduced* the path, and the id stays
/// a fact about where content entered history rather than about where the file
/// currently sits.
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

/// The commit whose exact tree seeds the workspace, or `None` for an unborn
/// HEAD.
///
/// Split out of [`resolve_workspace_seed`] so a bounded derivation can learn
/// which tree the seed will still need before it starts dropping the ones
/// nothing reads again. Both callers resolve HEAD by this one rule.
fn resolve_workspace_seed_commit(
    snapshot: &LosslessGitRepository,
    bodies: &BTreeMap<ExternalObjectId, Vec<u8>>,
    hash_kind: gix::hash::Kind,
) -> Result<Option<GitObjectId>> {
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
        return Ok(None);
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
    Ok(Some(peel_to_commit(object, bodies, hash_kind)?))
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
            // The merge's own tree carries one more file than any parent: the
            // exact body of `config/.gitignore`, which the merge removes
            // relative to its first parent while branches one and three still
            // carry it, at a path nothing else has. That is one artifact that
            // moved through a merge, and the resolution has to report it as one
            // update rather than as a removal and an addition of one identity.
            write(&repo, "config/generated-rules.txt", b"*.generated\n");
            git_ok(&repo, ["add", "config/generated-rules.txt"]);
            git_ok(&repo, ["commit", "--amend", "--no-edit"]);
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

    /// Deterministic historical semantics for one change, so the two
    /// enrichment paths can be handed exactly the same deltas.
    ///
    /// Empty deltas cannot tell those paths apart. `entity_deltas` and
    /// `relation_deltas` are part of what `compute_semantic_change_id` seals,
    /// so a comparison that leaves both empty grades every id as an
    /// unenriched change's id and proves nothing about enrichment itself.
    /// These carry real content, and the ids fall out of it.
    #[cfg(unix)]
    fn historical_deltas_for(index: usize) -> (Vec<EntityDelta>, Vec<RelationDelta>) {
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId,
            FingerprintAlgorithm, GraphNodeId, LanguageId, Relation, RelationId, RelationKind,
            RelationOrigin, SemanticFingerprint, Visibility,
        };

        let file = format!("src/commit_{index}.rs");
        let entity = |name: &str, line: u32, seed: u8| Entity {
            id: EntityId::from_content(&file, name, "function", line),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([seed; 32]),
                signature_hash: Hash256::from_bytes([seed ^ 0x11; 32]),
                behavior_hash: Hash256::from_bytes([seed ^ 0x22; 32]),
                equivalence_hash: Hash256::from_bytes([seed ^ 0x33; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file.clone())),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Private,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let seed = u8::try_from(index).unwrap_or(u8::MAX);
        let added = entity("added", 1, 0x10 ^ seed);
        let before = entity("edited", 9, 0x40);
        let after = entity("edited", 9, 0x50 ^ seed);
        let relation = Relation {
            id: RelationId::from_content(&added.id.to_string(), &after.id.to_string(), "calls"),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(added.id),
            dst: GraphNodeId::Entity(after.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };

        (
            vec![
                EntityDelta::Added { new: added },
                EntityDelta::Modified {
                    old: before,
                    new: after,
                },
            ],
            vec![RelationDelta::Added { new: relation }],
        )
    }

    #[cfg(unix)]
    #[test]
    fn spooled_history_preserves_enrichment_and_refuses_missing_or_reordered_records() {
        let fixture = SemanticFixture::octopus_polyglot();
        let snapshot = capture_lossless_git_repository(
            &fixture.repo,
            RepositoryId::new("spooled-history").unwrap(),
            &fixture.blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &fixture.blob_store).unwrap();
        // Keyed by change id, not by position, so the whole-plan arm and the
        // streaming arm bind the same deltas to the same change however each
        // one reaches it.
        let deltas_by_change = plan
            .changes
            .ids()
            .enumerate()
            .map(|(index, id)| (id, historical_deltas_for(index)))
            .collect::<BTreeMap<_, _>>();
        let bindings = deltas_by_change
            .iter()
            .map(|(id, (entity_deltas, relation_deltas))| {
                HistoricalSemanticBinding::owned(
                    *id,
                    entity_deltas.clone(),
                    relation_deltas.clone(),
                )
            })
            .collect();
        let legacy = plan
            .clone()
            .with_historical_semantics(&fixture.blob_store, bindings)
            .unwrap();
        let streamed = plan
            .clone()
            .enrich_with_historical_semantics(&fixture.blob_store, &mut |change, _tree| {
                let (entity_deltas, relation_deltas) = deltas_by_change
                    .get(&change.id)
                    .expect("every held change was given deltas")
                    .clone();
                Ok(HistoricalSemanticBinding::owned(
                    change.id,
                    entity_deltas,
                    relation_deltas,
                ))
            })
            .unwrap();
        assert_eq!(streamed, legacy);
        // The equality above is only worth its name while the deltas it
        // compares are real. Without this, a future edit that empties them
        // leaves a green test grading the unenriched case again.
        for change in streamed.changes.iter() {
            let change = change.unwrap();
            assert!(
                !change.entity_deltas.is_empty() && !change.relation_deltas.is_empty(),
                "change {} was compared without enrichment",
                change.id
            );
        }
        streamed.validate(&fixture.blob_store).unwrap();
        let admitted = admit_semantic_git_import(&streamed, &fixture.blob_store).unwrap();
        admitted.validate(&fixture.blob_store).unwrap();

        for remove in [false, true] {
            let mut malformed = plan.clone();
            let mut records = malformed
                .changes
                .iter()
                .collect::<Result<Vec<_>>>()
                .unwrap();
            if remove {
                records.pop();
            } else {
                records.swap(0, 1);
            }
            malformed.changes = SemanticChangeSpool::from_changes(fixture.blob_store.root(), records).unwrap();
            assert!(malformed.validate(&fixture.blob_store).is_err());

            let mut malformed = admitted.clone();
            let mut records = malformed
                .changes
                .iter()
                .collect::<Result<Vec<_>>>()
                .unwrap();
            if remove {
                records.pop();
            } else {
                records.swap(0, 1);
            }
            malformed.changes = SemanticChangeSpool::from_changes(fixture.blob_store.root(), records).unwrap();
            assert!(malformed.validate(&fixture.blob_store).is_err());
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
        assert_eq!(second.commit_tree_hashes.len(), 6);
        assert_eq!(second.content.trees.len(), 6);
        // The plan names every tree by hash and holds none; a test that wants
        // to look inside one derives them whole, and each one it derives is
        // the tree the plan named.
        let trees = derive_commit_trees(&snapshot, &fixture.blob_store).unwrap();
        assert_eq!(trees.len(), 6);
        for (oid, tree) in &trees {
            assert_eq!(
                second.commit_tree_hashes.get(oid),
                Some(&compute_resolved_tree_hash(tree).unwrap()),
                "the plan's hash for {oid} is not the hash of its derived tree"
            );
        }
        assert!(second.changes.iter().all(|change| {
            let change = change.unwrap();
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
            second.commit_tree_hashes.get(&fixture.empty),
            second.commit_tree_hashes.get(&fixture.initial)
        );
        assert_eq!(trees.get(&fixture.empty), trees.get(&fixture.initial));
        assert_eq!(
            merge_change.parents,
            [fixture.empty, fixture.one, fixture.two, fixture.three]
                .map(|oid| alias_for_oid(&second, oid).change_id)
        );

        let initial_tree = trees.get(&fixture.initial).unwrap();
        let merge_tree = trees.get(&fixture.merge).unwrap();
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
            artifact_id(trees.get(&fixture.one).unwrap(), b"branch-one.txt"),
            artifact_id(merge_tree, b"branch-one.txt")
        );
        let branch_same_a = artifact_id(trees.get(&fixture.one).unwrap(), b"same-a.bin");
        let branch_same_b = artifact_id(trees.get(&fixture.two).unwrap(), b"same-b.bin");
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
        assert_eq!(admitted.commit_tree_hashes, semantic.commit_tree_hashes);
        assert_eq!(admitted.content, semantic.content);
        assert_eq!(admitted.refs, semantic.refs);
        assert_eq!(admitted.head, semantic.head);
        assert_eq!(admitted.workspace_seed, semantic.workspace_seed);
        assert_eq!(admitted.changes.len(), semantic.changes.len());
        assert_eq!(admitted.aliases.len(), semantic.aliases.len());
        assert_eq!(
            admitted.commit_policies.len(),
            semantic.commit_tree_hashes.len()
        );
        let trees = derive_commit_trees(&snapshot, &fixture.blob_store).unwrap();

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
            let tree_entry = trees
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

        // Admission changes no tree: the admitted plan names the same tree
        // for the merge, by the hash of the tree derived from raw objects.
        let merge_tree = trees.get(&fixture.merge).unwrap();
        assert_eq!(
            admitted.commit_tree_hashes.get(&fixture.merge),
            Some(&compute_resolved_tree_hash(merge_tree).unwrap())
        );

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
        assert_eq!(
            transaction.changes,
            admitted.changes.iter().collect::<Result<Vec<_>>>().unwrap()
        );
        assert_eq!(transaction.aliases, admitted.aliases);
        assert!(transaction.git_authority_delta.is_none());
        assert!(transaction.workspace_mutation.is_none());
        assert!(transaction.collaboration_delta.is_none());
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

    /// What one conversion costs in whole-repository decompressions.
    ///
    /// The number is the point. Every step below asks for the same object
    /// closure over the same unchanged objects, and before the closure was
    /// shared each ask rebuilt it from the CAS: reading and verifying every
    /// object body in the repository. On this fixture the repository is three
    /// objects, so the rebuilds are free and only the COUNT is visible. On the
    /// 1,200-commit flask corpus each one is 162.5 MiB decompressed against
    /// 13 MB packed, which is what made this the conversion wall.
    ///
    /// Deliberately not a threshold. A test that asserted "fewer than before"
    /// would keep passing as the count crept back up, so this pins the exact
    /// number and fails in both directions.
    #[test]
    fn one_conversion_rebuilds_the_object_closure_once() {
        let root = tempdir().unwrap();
        let repo = root.path().join("source");
        fs::create_dir(&repo).unwrap();
        git_ok(&repo, ["init", "--initial-branch=main"]);
        configure_git(&repo);
        write(&repo, "lib.rs", b"pub fn f() -> u32 { 1 }\n");
        git_ok(&repo, ["add", "--all"]);
        git_ok(&repo, ["commit", "-m", "initial"]);
        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();

        let before = crate::lossless::closure_reconstruction_count();
        let snapshot = capture_lossless_git_repository(
            &repo,
            RepositoryId::new("closure-count").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        // The two proofs a conversion runs over the same objects: the plan
        // re-derived from raw objects, and the enriched fold checked against
        // that derivation.
        plan.validate(&blob_store).unwrap();
        let admitted = admit_semantic_git_import(&plan, &blob_store).unwrap();
        admitted.validate(&blob_store).unwrap();
        let rebuilds = crate::lossless::closure_reconstruction_count() - before;

        assert_eq!(
            rebuilds, 1,
            "one conversion over one unchanged object set must decompress that set ONCE; \
             {rebuilds} rebuilds means the closure is being rebuilt per caller again, which is \
             the conversion wall this sharing removed"
        );
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
        let mut changes = mutated.changes.iter().collect::<Result<Vec<_>>>().unwrap();
        changes[0].message.push_str("tampered");
        mutated.changes = SemanticChangeSpool::from_changes(blob_store.root(), changes).unwrap();
        assert!(matches!(
            mutated.validate(&blob_store),
            Err(GitError::InvalidSnapshot(_))
        ));
        // The plan names its trees by hash and carries what the seal reads
        // from them in their place, so both are checked against the
        // re-derivation the way the trees themselves used to be: a hash that
        // names a tree the raw objects do not derive, or a content summary
        // that describes one, is refused at the commit it belongs to.
        let mut mutated = plan.clone();
        let (oid, hash) = mutated
            .commit_tree_hashes
            .iter()
            .next()
            .map(|(oid, hash)| (*oid, *hash))
            .unwrap();
        let mut bytes = *hash.as_bytes();
        bytes[0] ^= 0xff;
        mutated
            .commit_tree_hashes
            .insert(oid, Hash256::from_bytes(bytes));
        assert!(matches!(
            mutated.validate(&blob_store),
            Err(GitError::InvalidSnapshot(_))
        ));
        let mut mutated = plan.clone();
        mutated
            .content
            .trees
            .get_mut(&oid)
            .unwrap()
            .regular_file_entries += 1;
        assert!(matches!(
            mutated.validate(&blob_store),
            Err(GitError::InvalidSnapshot(_))
        ));
        let mut mutated = plan.clone();
        mutated
            .content
            .identities
            .insert(Hash256::from_bytes([7; 32]), repo_path(b"phantom"));
        assert!(matches!(
            mutated.validate(&blob_store),
            Err(GitError::InvalidSnapshot(_))
        ));

        let ignore_hash = match derive_commit_trees(&snapshot, &blob_store)
            .unwrap()
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

    /// The delta-based resolution derives exactly what the whole-tree
    /// resolution derived, commit for commit.
    ///
    /// The identity rule and the delta shape are what every admitted store's
    /// change identities rest on, so they are pinned here against the
    /// algorithm they replaced, kept verbatim as the oracle: flatten the
    /// commit's whole tree, assign identities over every path, and diff two
    /// whole trees. The new path never sees a whole tree of a commit; it sees
    /// the leaves that differ from the first parent. Both walk the octopus
    /// fixture, which carries additions, removals, a mode flip, a symlink
    /// retarget, identities carried in from secondary parents and the
    /// ambiguous pair that must not be, and a second repository whose paths
    /// change shape between a file and a directory.
    #[cfg(unix)]
    #[test]
    fn delta_resolution_matches_the_whole_tree_oracle() {
        let fixture = SemanticFixture::octopus_polyglot();
        let snapshot = capture_lossless_git_repository(
            &fixture.repo,
            RepositoryId::new("semantic-oracle").unwrap(),
            &fixture.blob_store,
        )
        .unwrap();
        let shapes = oracle::compare_every_commit(&snapshot, &fixture.blob_store);
        assert_eq!(shapes.commits, 6);
        assert!(shapes.added > 0 && shapes.removed > 0 && shapes.updated > 0);

        let root = tempdir().unwrap();
        let repo = root.path().join("shapes");
        fs::create_dir(&repo).unwrap();
        git_ok(&repo, ["init", "--initial-branch=main"]);
        configure_git(&repo);
        write(&repo, "thing", b"a file\n");
        write(&repo, "dir/keep.txt", b"kept\n");
        write(&repo, "dir/nested/deep.txt", b"deep\n");
        git_ok(&repo, ["add", "--all"]);
        git_ok(&repo, ["commit", "-m", "file and directory"]);
        // The file becomes a directory, the nested directory becomes a file,
        // and an untouched sibling stays where it is.
        fs::remove_file(repo.join("thing")).unwrap();
        write(&repo, "thing/inside.txt", b"now a directory\n");
        fs::remove_dir_all(repo.join("dir/nested")).unwrap();
        write(&repo, "dir/nested", b"now a file\n");
        git_ok(&repo, ["add", "--all"]);
        git_ok(&repo, ["commit", "-m", "shapes change"]);
        // And back again, with a body change on the untouched sibling.
        fs::remove_dir_all(repo.join("thing")).unwrap();
        write(&repo, "thing", b"a file again\n");
        write(&repo, "dir/keep.txt", b"kept, edited\n");
        git_ok(&repo, ["add", "--all"]);
        git_ok(&repo, ["commit", "-m", "shapes change back"]);
        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repo,
            RepositoryId::new("semantic-oracle-shapes").unwrap(),
            &blob_store,
        )
        .unwrap();
        let shapes = oracle::compare_every_commit(&snapshot, &blob_store);
        assert_eq!(shapes.commits, 3);
        assert!(shapes.added > 0 && shapes.removed > 0 && shapes.updated > 0);
    }

    /// The whole-tree resolution this module replaced, kept verbatim as the
    /// oracle for [`delta_resolution_matches_the_whole_tree_oracle`].
    #[cfg(unix)]
    mod oracle {
        use std::collections::{BTreeMap, BTreeSet, HashMap};

        use kin_blobs::BlobStore;
        use kin_model::{
            ArtifactId, GitObjectId, RepoPath, ResolvedArtifact, ResolvedTree, TreeDelta, TreeEntry,
        };

        use super::super::{
            gix_hash_kind, introduced_artifact_id, parse_commits, resolve_tree_transition,
            topological_commit_order, RawTreeEntry, TreeDecoder,
        };
        use crate::error::{GitError, Result};
        use crate::lossless::{validate_snapshot, LosslessGitRepository};

        pub(super) struct ComparedShapes {
            pub(super) commits: usize,
            pub(super) added: usize,
            pub(super) removed: usize,
            pub(super) updated: usize,
        }

        /// Resolve every commit both ways and require the trees and deltas to
        /// agree, returning what shapes the comparison covered.
        pub(super) fn compare_every_commit(
            snapshot: &LosslessGitRepository,
            blob_store: &BlobStore,
        ) -> ComparedShapes {
            let bodies = validate_snapshot(snapshot, blob_store).unwrap();
            let records = snapshot
                .objects
                .iter()
                .map(|record| (record.object, record))
                .collect::<BTreeMap<_, _>>();
            let hash_kind = gix_hash_kind(snapshot.object_format);
            let commits = parse_commits(snapshot, &bodies, hash_kind).unwrap();
            let order = topological_commit_order(&commits).unwrap();
            let decoder = TreeDecoder::new(hash_kind, &bodies, &records);
            let mut trees = BTreeMap::<GitObjectId, ResolvedTree>::new();
            let mut known = BTreeSet::new();
            // The oracle accumulates known identities from each whole resolved
            // tree. The product accumulates them from the Added deltas alone
            // (`build_semantic_git_import_plan`), on the rule that an added path
            // is the only way a new identity enters history. The two agree by
            // induction, and the induction is what this second set checks at
            // every commit, because feeding both algorithms the same
            // whole-tree set would leave the product's own rule ungraded.
            let mut known_from_added = BTreeSet::new();
            let mut shapes = ComparedShapes {
                commits: 0,
                added: 0,
                removed: 0,
                updated: 0,
            };
            for oid in order {
                let parsed = commits.get(&oid).unwrap();
                let first_parent = parsed
                    .parents
                    .first()
                    .map(|parent| trees.get(parent).unwrap().clone())
                    .unwrap_or_default();
                let secondary = parsed
                    .parents
                    .iter()
                    .skip(1)
                    .map(|parent| trees.get(parent).unwrap())
                    .collect::<Vec<_>>();

                let raw_tree = flatten(&decoder, parsed.tree);
                let expected_tree =
                    assign_artifact_identities(oid, &first_parent, &secondary, raw_tree, &known)
                        .unwrap();
                let expected_deltas = exact_tree_deltas(&first_parent, &expected_tree);

                let changes = decoder
                    .diff_trees(
                        parsed
                            .parents
                            .first()
                            .map(|parent| commits.get(parent).unwrap().tree),
                        parsed.tree,
                    )
                    .unwrap();
                let (deltas, tree) =
                    resolve_tree_transition(oid, &first_parent, &secondary, changes, &known)
                        .unwrap();
                assert_eq!(
                    tree, expected_tree,
                    "commit {oid} resolved a different tree"
                );
                assert_eq!(
                    deltas, expected_deltas,
                    "commit {oid} resolved different tree deltas"
                );
                for delta in &deltas {
                    match delta {
                        TreeDelta::Added { .. } => shapes.added += 1,
                        TreeDelta::Removed { .. } => shapes.removed += 1,
                        TreeDelta::Updated { .. } => shapes.updated += 1,
                    }
                }
                known.extend(tree.artifacts().map(|artifact| artifact.artifact_id));
                known_from_added.extend(
                    deltas
                        .iter()
                        .filter(|delta| matches!(delta, TreeDelta::Added { .. }))
                        .map(|delta| delta.artifact_id()),
                );
                assert_eq!(
                    known_from_added, known,
                    "commit {oid}: accumulating identities from Added deltas alone diverged from \
                     accumulating them from every resolved tree"
                );
                trees.insert(oid, tree);
                shapes.commits += 1;
            }
            shapes
        }

        fn flatten(
            decoder: &TreeDecoder<'_>,
            tree_oid: GitObjectId,
        ) -> BTreeMap<RepoPath, TreeEntry> {
            fn walk(
                decoder: &TreeDecoder<'_>,
                tree_oid: GitObjectId,
                prefix: &mut Vec<u8>,
                out: &mut BTreeMap<RepoPath, TreeEntry>,
            ) {
                for (name, entry) in decoder.direct_entries(tree_oid).unwrap() {
                    let mark = prefix.len();
                    if !prefix.is_empty() {
                        prefix.push(b'/');
                    }
                    prefix.extend_from_slice(&name);
                    match entry {
                        RawTreeEntry::Tree(sub) => walk(decoder, sub, prefix, out),
                        RawTreeEntry::Leaf(leaf) => {
                            assert!(out
                                .insert(RepoPath::from_bytes(prefix.clone()).unwrap(), leaf)
                                .is_none());
                        }
                    }
                    prefix.truncate(mark);
                }
            }
            let mut out = BTreeMap::new();
            walk(decoder, tree_oid, &mut Vec::new(), &mut out);
            out
        }

        fn assign_artifact_identities(
            introducing_commit: GitObjectId,
            first_parent: &ResolvedTree,
            secondary_parents: &[&ResolvedTree],
            raw_tree: BTreeMap<RepoPath, TreeEntry>,
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
                let artifact_id = if let Some(first_parent_artifact) =
                    first_parent.artifact_at_path(&path)
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
                            if known_artifact_ids.contains(&derived) || assigned.contains(&derived)
                            {
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
    }

    #[cfg(unix)]
    fn change_for_oid(plan: &SemanticGitImportPlan, oid: GitObjectId) -> SemanticChange {
        plan.changes.read_by_oid(&oid).unwrap().unwrap()
    }

    #[cfg(unix)]
    fn alias_for_oid(plan: &SemanticGitImportPlan, oid: GitObjectId) -> &ExternalChangeAlias {
        plan.aliases.iter().find(|alias| alias.oid == oid).unwrap()
    }

    #[cfg(unix)]
    fn admitted_change_for_oid(
        plan: &AdmittedSemanticGitImportPlan,
        oid: GitObjectId,
    ) -> SemanticChange {
        plan.changes.read_by_oid(&oid).unwrap().unwrap()
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
