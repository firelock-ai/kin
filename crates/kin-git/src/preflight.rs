// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Read-only authority preflight for one exact Git workspace migration.
//!
//! A lossless object/ref snapshot proves committed repository history, not the
//! mutable Git index or materialized checkout. This boundary independently
//! observes the source index and every tracked worktree leaf against the
//! committed workspace seed before a later admission lane may construct a
//! workspace mutation. It never executes hooks or filters, never recurses into
//! gitlinks, and never manufactures an admission token.
//!
//! Repository authority is the committed workspace seed and nothing else, so a
//! path that differs from it is reported rather than refused: an index entry
//! that is not the committed one, a tracked leaf the worktree materializes
//! differently, a committed path the worktree no longer carries, and a worktree
//! path that is neither tracked nor ignored are all recorded as divergence and
//! carried in the proof. That is what a working repository looks like, and the
//! daemon admits exactly this delta as workspace state on its first run.
//! Ambiguity about the source itself still refuses, because there the committed
//! state a migration would seal is not decidable: an in-progress Git operation,
//! a conflicted or sparse index, an entry Git has been told not to compare, and
//! a materialized nested repository.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use gix::bstr::ByteSlice;
use kin_blobs::{digest, BlobStore};
use kin_model::{
    compute_resolved_tree_hash, ExternalObjectKind, GitObjectId, Hash256, RefTarget, RepoPath,
    RepositoryId, RepositoryRefState, TreeEntry, WorkspaceHead,
};

use crate::admission_blockers::effective_hook_surface;
use crate::error::{
    GitCheckoutFilterFact, GitError, LocalGitHookExecutability, LocalGitHookFact, LocalGitHookKind,
    RegisteredGitWorktreeFact, RegisteredGitWorktreeKind, Result, UntolerableGitWorktree,
};
use crate::lossless::{
    capture_lossless_git_repository, open_repo, reject_shallow_repository, GitObjectFormat,
    LosslessGitRepository,
};
use crate::semantic_import::SemanticGitImportPlan;

/// Successful, point-in-time proof that one Git workspace can be admitted
/// without flattening index or worktree state into repository authority.
///
/// This proves only the Git/source boundary. It does not establish that every
/// imported historical tree has a branch-versioned shared admission policy,
/// and therefore is not by itself authorization to admit the current
/// policy-free semantic import plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitMigrationPreflightProof {
    pub repository_id: RepositoryId,
    pub source_worktree: PathBuf,
    pub source_git_dir: PathBuf,
    pub object_format: GitObjectFormat,
    /// Material workspace HEAD from the semantic seed. The lossless snapshot
    /// fingerprint separately binds exact raw Git HEAD identity.
    pub head: WorkspaceHead,
    pub refs: RepositoryRefState,
    pub base_target: Option<RefTarget>,
    pub base_commit_oid: Option<GitObjectId>,
    pub base_tree_hash: Option<Hash256>,
    pub snapshot_fingerprint: Hash256,
    pub semantic_plan_fingerprint: Hash256,
    pub index: GitIndexPreflightProof,
    pub tracked_worktree: GitTrackedWorktreeProof,
    /// Index and worktree state that is not the committed workspace seed.
    /// Observed, never admitted: authority is the seed alone.
    pub workspace_divergence: GitWorkspaceDivergenceFacts,
    pub ignored_local: IgnoredLocalWorktreeFact,
    pub compatibility: GitMigrationCompatibilityFacts,
    pub remote_mapping: GitRemoteMappingFacts,
    pub observation_fingerprint: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitIndexPreflightProof {
    /// Whether a physical index file existed. Absence is admissible only for a
    /// truly unborn HEAD whose expected materialized tree is empty.
    pub present: bool,
    pub at_rest_checksum: Option<GitObjectId>,
    pub raw_file_hash: Hash256,
    pub logical_fingerprint: Hash256,
    pub entry_count: usize,
    pub sparse: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTrackedWorktreeProof {
    pub entry_count: usize,
    pub gitlink_count: usize,
    /// Exact Git paths that this host cannot name losslessly and therefore
    /// proves only as graph-owned, physically absent entries.
    pub host_unrepresentable_count: usize,
    pub fingerprint: Hash256,
}

/// Everything about one source that is not its committed workspace seed.
///
/// A working repository is edited, and none of that editing is repository
/// authority: the seed is the committed tree, the delta is workspace state, and
/// the daemon admits it through the same path it admits every later edit. The
/// proof therefore carries the delta instead of refusing it, so init can say
/// what it saw and what will happen to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWorkspaceDivergenceFacts {
    /// Divergent paths, grouped by kind and ordered by path within a kind.
    pub entries: Vec<GitWorkspaceDivergence>,
    /// Untracked paths found past the listing cap, counted rather than kept.
    pub untracked_beyond_cap: usize,
    pub fingerprint: Hash256,
}

impl GitWorkspaceDivergenceFacts {
    /// The facts of a source with nothing to disclose.
    ///
    /// Its fingerprint is the one an observation of a repository that matched
    /// its committed state produces, so a caller that has no source to observe
    /// and one that observed no difference are not distinguishable by identity.
    pub fn none() -> Self {
        DivergenceLog::default().finish()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.untracked_beyond_cap == 0
    }

    /// Divergent paths observed, including the untracked ones past the cap.
    pub fn observed_paths(&self) -> usize {
        self.entries.len() + self.untracked_beyond_cap
    }

    pub fn of_kind(
        &self,
        kind: GitWorkspaceDivergenceKind,
    ) -> impl Iterator<Item = &GitWorkspaceDivergence> {
        self.entries.iter().filter(move |entry| entry.kind == kind)
    }
}

/// One path whose source state differs from the committed workspace seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWorkspaceDivergence {
    pub path: RepoPath,
    pub kind: GitWorkspaceDivergenceKind,
    /// One sentence naming what differs, for a kind that has more than one way
    /// of differing. Empty when the kind already says everything.
    pub detail: String,
    /// Identity of the worktree bytes this observation read, where it read
    /// them. A divergence proved by reading content carries what it read, so
    /// repeating the observation detects content that moved under it.
    pub observed: Option<Hash256>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWorkspaceDivergenceKind {
    /// Index entry that is not the committed entry for its path, or is a path
    /// the committed tree does not carry at all.
    Staged,
    /// Committed path the index no longer carries.
    StagedRemoval,
    /// Tracked path the worktree materializes differently than committed.
    Modified,
    /// Committed path the worktree does not materialize at all.
    Missing,
    /// Worktree path that is neither tracked nor ignored.
    Untracked,
}

impl GitWorkspaceDivergenceKind {
    /// Stable ordering and encoding code, so grouping and the fingerprint agree.
    fn code(self) -> u64 {
        match self {
            Self::Staged => 1,
            Self::StagedRemoval => 2,
            Self::Modified => 3,
            Self::Missing => 4,
            Self::Untracked => 5,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::StagedRemoval => "staged removal",
            Self::Modified => "modified",
            Self::Missing => "missing",
            Self::Untracked => "untracked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredLocalWorktreeFact {
    /// Ordered, path-sanitized local ignore inputs that justified exclusions.
    /// Tracked `.gitignore` files are intentionally absent: they remain part
    /// of shared repository history.
    pub inputs: Vec<GitLocalIgnoreInputFact>,
    /// Case behavior used while matching the frozen inputs.
    pub ignore_case: bool,
    pub entries: Vec<IgnoredLocalEntry>,
    pub fingerprint: Hash256,
}

impl IgnoredLocalWorktreeFact {
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitLocalIgnoreInputFact {
    pub source_kind: GitLocalIgnoreSourceKind,
    pub order: usize,
    pub body: Vec<u8>,
    pub body_hash: Hash256,
    pub body_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitLocalIgnoreSourceKind {
    ResolvedGlobalExcludes,
    RepositoryInfoExclude,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredLocalEntry {
    pub path: RepoPath,
    pub kind: IgnoredLocalEntryKind,
    pub byte_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoredLocalEntryKind {
    File,
    Symlink,
    Directory,
    Other,
}

/// Compatibility surfaces intentionally excluded from graph authority.
///
/// Successful preflight requires the three blocker collections to be empty;
/// the explicit shape keeps that fact available to later admission code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitMigrationCompatibilityFacts {
    pub other_registered_worktrees: Vec<RegisteredGitWorktreeFact>,
    pub local_hooks: Vec<LocalGitHookFact>,
    pub configured_custom_hooks_path: bool,
    pub checkout_filters: Vec<GitCheckoutFilterFact>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GitRemoteMappingFacts {
    pub remotes: Vec<GitRemoteConfigFact>,
    pub branch_tracking: Vec<GitBranchTrackingFact>,
    /// Effective repository-local `remote.pushDefault`, if explicitly set.
    pub remote_push_default: Option<Vec<u8>>,
    /// Effective repository-local `push.default`, if explicitly set.
    pub push_default: Option<Vec<u8>>,
    /// Effective repository-local `push.autoSetupRemote`, if explicitly set.
    ///
    /// Modelled rather than admitted silently. It decides whether a push of a
    /// branch with no upstream publishes and records one instead of refusing,
    /// which is transport behaviour Kin has to be able to restore on eject.
    pub push_auto_setup_remote: Option<Vec<u8>>,
}

impl GitRemoteMappingFacts {
    pub fn is_empty(&self) -> bool {
        self.remotes.is_empty()
            && self.branch_tracking.is_empty()
            && self.remote_push_default.is_none()
            && self.push_default.is_none()
            && self.push_auto_setup_remote.is_none()
    }
}

impl fmt::Debug for GitRemoteMappingFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitRemoteMappingFacts")
            .field("remote_count", &self.remotes.len())
            .field("branch_tracking_count", &self.branch_tracking.len())
            .field(
                "remote_push_default_present",
                &self.remote_push_default.is_some(),
            )
            .field("push_default_present", &self.push_default.is_some())
            .field(
                "push_auto_setup_remote_present",
                &self.push_auto_setup_remote.is_some(),
            )
            .field("values", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GitRemoteConfigFact {
    pub name: Vec<u8>,
    /// Ordered repository-local `remote.<name>.url` values.
    pub fetch_urls: Vec<Vec<u8>>,
    /// Ordered repository-local `remote.<name>.pushurl` values. An empty list
    /// preserves the explicit absence that makes Git fall back to fetch URLs.
    pub push_urls: Vec<Vec<u8>>,
    /// Ordered repository-local `remote.<name>.fetch` refspecs.
    pub fetch_refspecs: Vec<Vec<u8>>,
    /// Ordered repository-local `remote.<name>.push` refspecs.
    pub push_refspecs: Vec<Vec<u8>>,
}

impl fmt::Debug for GitRemoteConfigFact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitRemoteConfigFact")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("fetch_url_count", &self.fetch_urls.len())
            .field("push_url_count", &self.push_urls.len())
            .field("fetch_refspec_count", &self.fetch_refspecs.len())
            .field("push_refspec_count", &self.push_refspecs.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GitBranchTrackingFact {
    pub branch: Vec<u8>,
    pub remote: Option<Vec<u8>>,
    pub merge_refs: Vec<Vec<u8>>,
    pub push_remote: Option<Vec<u8>>,
}

impl fmt::Debug for GitBranchTrackingFact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitBranchTrackingFact")
            .field("branch", &String::from_utf8_lossy(&self.branch))
            .field("remote_present", &self.remote.is_some())
            .field("merge_ref_count", &self.merge_refs.len())
            .field("push_remote_present", &self.push_remote.is_some())
            .field("values", &"<redacted>")
            .finish()
    }
}

/// Untracked paths kept by name before the rest are only counted.
///
/// A worktree carrying an unignored build directory holds hundreds of
/// thousands of them. The count stays exact because the walk has to visit every
/// entry anyway to prove the tracked ones; only the list is bounded.
const LISTED_UNTRACKED_CAP: usize = 512;

/// Collects divergence while the index and worktree are observed.
#[derive(Debug, Default)]
struct DivergenceLog {
    entries: Vec<GitWorkspaceDivergence>,
    untracked_listed: usize,
    untracked_beyond_cap: usize,
}

impl DivergenceLog {
    fn record(
        &mut self,
        path: RepoPath,
        kind: GitWorkspaceDivergenceKind,
        detail: impl Into<String>,
        observed: Option<Hash256>,
    ) {
        self.entries.push(GitWorkspaceDivergence {
            path,
            kind,
            detail: detail.into(),
            observed,
        });
    }

    /// Whether the index itself is carrying something the commit does not.
    fn records_index_state(&self) -> bool {
        self.entries.iter().any(|entry| {
            matches!(
                entry.kind,
                GitWorkspaceDivergenceKind::Staged | GitWorkspaceDivergenceKind::StagedRemoval
            )
        })
    }

    fn record_untracked(&mut self, path: RepoPath) {
        if self.untracked_listed >= LISTED_UNTRACKED_CAP {
            self.untracked_beyond_cap += 1;
            return;
        }
        self.untracked_listed += 1;
        self.record(path, GitWorkspaceDivergenceKind::Untracked, "", None);
    }

    fn finish(mut self) -> GitWorkspaceDivergenceFacts {
        self.entries.sort_by(|left, right| {
            (left.kind.code(), &left.path).cmp(&(right.kind.code(), &right.path))
        });
        let mut hash = FramedHash::new(b"kin.git.preflight.divergence.v1");
        hash.u64(self.entries.len() as u64);
        for entry in &self.entries {
            hash.bytes(entry.path.as_bytes());
            hash.u64(entry.kind.code());
            hash.bytes(entry.detail.as_bytes());
            match &entry.observed {
                Some(observed) => {
                    hash.u64(1);
                    hash.bytes(observed.as_bytes());
                }
                None => hash.u64(0),
            }
        }
        hash.u64(self.untracked_beyond_cap as u64);
        GitWorkspaceDivergenceFacts {
            entries: self.entries,
            untracked_beyond_cap: self.untracked_beyond_cap,
            fingerprint: hash.finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreflightObservation {
    snapshot: LosslessGitRepository,
    proof: GitMigrationPreflightProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedIndexEntry {
    mode: gix::index::entry::Mode,
    oid: GitObjectId,
    tree_entry: TreeEntry,
}

/// Prove the exact mutable Git boundary for a previously captured and planned
/// source repository.
///
/// The source repository is never mutated. The supplied blob store is used to
/// revalidate already-captured object bodies and workspace bytes. The entire
/// observation is repeated before returning to close the practical TOCTOU
/// window; any change fails closed.
///
/// This is the standalone form, for the first proof of an admission, where
/// there is nothing earlier to compare against. It is also the only form that
/// structurally revalidates the import plan, which is what makes it the
/// expensive one: see [`reprove_git_migration`] for what a later proof in the
/// same admission may reuse from it and why.
///
/// A later history-enrichment/admission step must still attach and validate
/// shared admission policy deltas before repository authority can be published.
pub fn preflight_git_migration(
    repo_path: &Path,
    snapshot: &LosslessGitRepository,
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
) -> Result<GitMigrationPreflightProof> {
    preflight_git_migration_with_hook(repo_path, snapshot, plan, blob_store, None, None, || {})
}

/// Repeat a source proof this admission already took, against that proof.
///
/// The invariant is the same one [`preflight_git_migration`] establishes: the
/// mutable Git boundary this admission is reading still holds exactly the
/// committed state the capture was taken from. What differs is only how much
/// work it takes to establish it a second time, and the whole of that
/// difference rests on `baseline` being a proof of the SAME source, snapshot,
/// and plan, taken earlier in this admission.
///
/// Two reuses follow from that, and neither weakens the proof:
///
/// The single observation. A standalone proof observes twice and requires the
/// two to agree, because on its own it has no earlier reading to be measured
/// against and a lone observation could be a torn read. A re-proof does have
/// one: `baseline`. Requiring one fresh observation to equal `baseline` is
/// strictly stronger than requiring two adjacent observations to equal each
/// other, because the baseline was taken minutes rather than seconds earlier,
/// so its window contains the doubled window entirely. A torn read still fails,
/// because a torn read does not equal the clean baseline either. Neither form
/// can see a source that changes and changes back between samples; adding a
/// third sample would not close that, and pretending it does is the reason the
/// doubling looked load-bearing.
///
/// The skipped plan revalidation. [`SemanticGitImportPlan::validate`] rebuilds
/// the entire plan from the captured objects and requires the rebuild to be
/// identical, which is the guard against a plan enriched with anything not
/// derivable from the source. It is a pure function of an immutable in-memory
/// plan and an append-only content-addressed store, so re-running it over the
/// same plan value cannot reach a different verdict. What it would catch, a
/// plan that is not the one the baseline proved, is caught instead by
/// `semantic_plan_fingerprint`, which is still derived fresh on every
/// observation and compared through the whole-proof comparison below.
pub fn reprove_git_migration(
    repo_path: &Path,
    baseline: &GitMigrationPreflightProof,
    snapshot: &LosslessGitRepository,
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
) -> Result<GitMigrationPreflightProof> {
    preflight_git_migration_with_hook(
        repo_path,
        snapshot,
        plan,
        blob_store,
        None,
        Some(ProofBaseline {
            proof: baseline,
            changed: "Git source proof changed before repository publication; retry from a fresh \
                      capture",
        }),
        || {},
    )
}

/// Repeat an exact Git source proof after Kin has atomically installed `.kin`.
///
/// Only the supplied real `.kin` directory at the canonical worktree root is
/// excluded from the worktree walk. Every Git object, ref, index byte, tracked
/// leaf, ignored-local fact, and any other untracked path remains subject to
/// the same proof as pre-publication migration, and the result must equal
/// `baseline` exactly.
///
/// This is the one proof publication itself can move, and it is why the
/// exclusion is spelled out rather than inferred: publication is a single
/// no-replace rename of a staged directory into the worktree root, so the only
/// difference from `baseline` it can legitimately produce is that `.kin` now
/// exists. Anything else this observes, a second path that appeared, a tracked
/// leaf whose bytes moved, an object or ref that is no longer the captured one,
/// is either publication writing somewhere it must not or a non-cooperating
/// writer racing the rename. Both are refusals, and because the rename has
/// already happened they are detections rather than preventions: the caller
/// reports them as a published repository that is not safe to use without
/// recovery.
///
/// It observes once for the reasons given at [`reprove_git_migration`].
pub fn reprove_git_migration_after_publication(
    repo_path: &Path,
    published_kin_dir: &Path,
    baseline: &GitMigrationPreflightProof,
    snapshot: &LosslessGitRepository,
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
) -> Result<GitMigrationPreflightProof> {
    let source_worktree =
        fs::canonicalize(repo_path).map_err(|error| GitError::io(repo_path, error))?;
    let published_kin_dir = canonical_published_kin_dir(&source_worktree, published_kin_dir)?;
    preflight_git_migration_with_hook(
        &source_worktree,
        snapshot,
        plan,
        blob_store,
        Some(&published_kin_dir),
        Some(ProofBaseline {
            proof: baseline,
            changed: "Git source proof changed across repository publication; published \
                      authority is not safe to use without recovery",
        }),
        || {},
    )
}

/// Repeat an exact Git source proof after publication, without a baseline.
///
/// The standalone post-publication form, kept for callers that have no earlier
/// proof of this source to measure against. An admission always does, and uses
/// [`reprove_git_migration_after_publication`].
pub fn preflight_git_migration_after_publication(
    repo_path: &Path,
    published_kin_dir: &Path,
    snapshot: &LosslessGitRepository,
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
) -> Result<GitMigrationPreflightProof> {
    let source_worktree =
        fs::canonicalize(repo_path).map_err(|error| GitError::io(repo_path, error))?;
    let published_kin_dir = canonical_published_kin_dir(&source_worktree, published_kin_dir)?;
    preflight_git_migration_with_hook(
        &source_worktree,
        snapshot,
        plan,
        blob_store,
        Some(&published_kin_dir),
        None,
        || {},
    )
}

/// The exact `.kin` a post-publication proof is allowed to exclude.
///
/// Only a real directory at the canonical worktree root qualifies. Resolving
/// through a symlink, or accepting a path elsewhere, would let the exclusion
/// hide a part of the worktree the proof is supposed to cover.
fn canonical_published_kin_dir(
    source_worktree: &Path,
    published_kin_dir: &Path,
) -> Result<PathBuf> {
    let expected_kin_dir = source_worktree.join(".kin");
    let metadata = fs::symlink_metadata(published_kin_dir)
        .map_err(|error| GitError::io(published_kin_dir, error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(preflight_error(format!(
            "published Kin repository is not a real directory: {}",
            published_kin_dir.display()
        )));
    }
    let published_kin_dir = fs::canonicalize(published_kin_dir)
        .map_err(|error| GitError::io(published_kin_dir, error))?;
    if published_kin_dir != expected_kin_dir {
        return Err(preflight_error(format!(
            "post-publication proof may exclude only {}",
            expected_kin_dir.display()
        )));
    }
    Ok(published_kin_dir)
}

/// An earlier proof of this same admission, and what to say when the source no
/// longer matches it.
///
/// Carrying the sentence here rather than leaving the comparison to the caller
/// is what keeps the cheaper single-observation path from being reachable
/// without one: the baseline is the argument that makes one observation
/// sufficient, so the type that authorizes it also performs the comparison.
#[derive(Clone, Copy)]
struct ProofBaseline<'a> {
    proof: &'a GitMigrationPreflightProof,
    changed: &'static str,
}

fn preflight_git_migration_with_hook(
    repo_path: &Path,
    snapshot: &LosslessGitRepository,
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
    published_kin_dir: Option<&Path>,
    baseline: Option<ProofBaseline<'_>>,
    after_first_observation: impl FnOnce(),
) -> Result<GitMigrationPreflightProof> {
    // Structurally rebuilding the plan is what a baselined re-proof reuses
    // rather than repeats; the binding comparison below is cheap and runs
    // either way. Both halves of the reasoning are at `reprove_git_migration`.
    if baseline.is_none() {
        plan.validate(blob_store)?;
    }
    bind_plan_to_snapshot(snapshot, plan)?;
    // A pure function of the plan, which no observation mutates. Derived once
    // per proof rather than once per observation, and still derived rather than
    // carried over from a baseline, so a plan that is not the proved one moves
    // the proof and fails the comparison.
    let semantic_plan_fingerprint = fingerprint_plan(plan)?;
    let expected = expected_index_entries(snapshot, plan)?;
    let observation = || {
        observe(
            repo_path,
            snapshot,
            plan,
            blob_store,
            &expected,
            published_kin_dir,
            semantic_plan_fingerprint,
        )
    };

    let Some(baseline) = baseline else {
        let first = observation()?;
        after_first_observation();
        let second = observation()?;
        if first != second {
            return Err(preflight_error(
                "Git source changed during migration preflight; retry from a fresh snapshot",
            ));
        }
        return Ok(second.proof);
    };

    let observed = observation()?;
    if observed.proof != *baseline.proof {
        return Err(preflight_error(baseline.changed));
    }
    Ok(observed.proof)
}

fn bind_plan_to_snapshot(
    snapshot: &LosslessGitRepository,
    plan: &SemanticGitImportPlan,
) -> Result<()> {
    if plan.repository_id != snapshot.repository_id
        || plan.object_format != snapshot.object_format
        || plan.external_objects != snapshot.objects
        || plan.refs != snapshot.refs
        || plan.head != snapshot.head
    {
        return Err(preflight_error(
            "semantic import plan is not bound to the supplied lossless snapshot",
        ));
    }
    Ok(())
}

fn observe(
    repo_path: &Path,
    expected_snapshot: &LosslessGitRepository,
    plan: &SemanticGitImportPlan,
    blob_store: &BlobStore,
    expected_entries: &BTreeMap<RepoPath, ExpectedIndexEntry>,
    published_kin_dir: Option<&Path>,
    semantic_plan_fingerprint: Hash256,
) -> Result<PreflightObservation> {
    let source_worktree =
        fs::canonicalize(repo_path).map_err(|error| GitError::io(repo_path, error))?;
    let snapshot = capture_lossless_git_repository(
        &source_worktree,
        expected_snapshot.repository_id.clone(),
        blob_store,
    )?;
    if snapshot != *expected_snapshot {
        return Err(preflight_error(
            "source HEAD, refs, or reachable object closure no longer matches the supplied snapshot",
        ));
    }

    let repo = open_repo(&source_worktree)?;
    reject_shallow_repository(&repo)?;
    reject_in_progress_operations(&repo)?;
    let source_git_dir = stable_path(repo.git_dir());
    let workdir = repo.workdir().ok_or_else(|| {
        preflight_error("migration preflight requires a materialized Git worktree")
    })?;
    if stable_path(workdir) != source_worktree {
        return Err(preflight_error(format!(
            "opened Git worktree {} does not match requested source {}",
            workdir.display(),
            source_worktree.display()
        )));
    }

    let (tolerated_worktrees, untolerable_worktrees) =
        classify_other_worktrees(&repo, other_registered_worktrees(&repo, &source_worktree)?)?;
    if !untolerable_worktrees.is_empty() {
        return Err(GitError::AdditionalWorktrees {
            count: untolerable_worktrees.len(),
            worktrees: untolerable_worktrees,
        });
    }

    let ambient_repo = open_repo_with_user_ignore_config(&source_worktree)?;
    if stable_path(ambient_repo.git_dir()) != stable_path(repo.git_dir())
        || stable_path(ambient_repo.common_dir()) != stable_path(repo.common_dir())
    {
        return Err(preflight_error(
            "resolved user ignore configuration opened a different Git repository",
        ));
    }

    let hook_surface = effective_hook_surface(&repo, &ambient_repo)?;
    let filters = checkout_filter_facts(&repo);
    if !hook_surface.hooks.is_empty() || !filters.is_empty() {
        return Err(GitError::LocalCompatibilityBlockers {
            hook_count: hook_surface.hooks.len(),
            custom_hooks_path: hook_surface.repository_scoped_hooks_path(),
            filter_count: filters.len(),
            hooks: hook_surface.hooks,
            filters,
        });
    }

    let remote_mapping = remote_mapping_facts(&repo)?;
    let absent_index_allowed = matches!(snapshot.head, WorkspaceHead::Symbolic { .. })
        && plan.workspace_seed.base_target.is_none()
        && plan.workspace_seed.base_commit_oid.is_none()
        && plan.workspace_seed.base_tree_hash.is_none()
        && expected_entries.is_empty();
    let (index_file, raw_index) = read_strict_index(&repo, absent_index_allowed)?;
    let mut divergence = DivergenceLog::default();
    let index = prove_index(
        &index_file,
        raw_index.as_deref(),
        expected_entries,
        &mut divergence,
    )?;
    // The tree extension caches the tree this index would write. An index that
    // carries staged work has not written that tree, and Git invalidates the
    // subtrees it covers rather than removing them, so resolving it against the
    // object database asks for an object the source has never had a reason to
    // create. The extension is verified where it describes something written.
    if !divergence.records_index_state() {
        index_file
            .verify_extensions(true, &repo.objects)
            .map_err(|error| preflight_error(format!("verify Git index extensions: {error}")))?;
    }
    let (tracked_worktree, ignored_local) = prove_worktree(
        &ambient_repo,
        &index_file,
        workdir,
        expected_entries,
        blob_store,
        published_kin_dir,
        &mut divergence,
    )?;
    let workspace_divergence = divergence.finish();
    let snapshot_fingerprint = fingerprint_snapshot(&snapshot);
    let compatibility = GitMigrationCompatibilityFacts {
        // Tolerated siblings are recorded rather than dropped. Both
        // observations carry them, so one appearing or vanishing mid-proof
        // fails the comparison instead of passing unnoticed.
        other_registered_worktrees: tolerated_worktrees,
        local_hooks: Vec::new(),
        configured_custom_hooks_path: false,
        checkout_filters: Vec::new(),
    };
    let mut proof = GitMigrationPreflightProof {
        repository_id: snapshot.repository_id.clone(),
        source_worktree,
        source_git_dir,
        object_format: snapshot.object_format,
        head: plan.workspace_seed.head.clone(),
        refs: snapshot.refs.clone(),
        base_target: plan.workspace_seed.base_target.clone(),
        base_commit_oid: plan.workspace_seed.base_commit_oid,
        base_tree_hash: plan.workspace_seed.base_tree_hash,
        snapshot_fingerprint,
        semantic_plan_fingerprint,
        index,
        tracked_worktree,
        workspace_divergence,
        ignored_local,
        compatibility,
        remote_mapping,
        observation_fingerprint: digest(b"kin.git.preflight.unset"),
    };
    proof.observation_fingerprint = fingerprint_proof(&proof);
    Ok(PreflightObservation { snapshot, proof })
}

fn expected_index_entries(
    snapshot: &LosslessGitRepository,
    plan: &SemanticGitImportPlan,
) -> Result<BTreeMap<RepoPath, ExpectedIndexEntry>> {
    let mut blob_oids = BTreeMap::<Hash256, GitObjectId>::new();
    for record in snapshot
        .objects
        .iter()
        .filter(|record| record.object.kind == ExternalObjectKind::Blob)
    {
        if let Some(previous) = blob_oids.insert(record.body_hash, record.object.oid) {
            if previous != record.object.oid {
                return Err(preflight_error(format!(
                    "blob body {} maps to multiple Git object IDs",
                    record.body_hash
                )));
            }
        }
    }

    let mut expected = BTreeMap::new();
    for artifact in plan.workspace_seed.base_tree.artifacts_by_path() {
        let entry = match artifact.entry {
            TreeEntry::Blob { hash, executable } => ExpectedIndexEntry {
                mode: if executable {
                    gix::index::entry::Mode::FILE_EXECUTABLE
                } else {
                    gix::index::entry::Mode::FILE
                },
                oid: *blob_oids.get(&hash).ok_or_else(|| {
                    preflight_error(format!(
                        "workspace blob {} at {} has no exact Git object identity",
                        hash, artifact.path
                    ))
                })?,
                tree_entry: artifact.entry,
            },
            TreeEntry::Symlink { target_blob } => ExpectedIndexEntry {
                mode: gix::index::entry::Mode::SYMLINK,
                oid: *blob_oids.get(&target_blob).ok_or_else(|| {
                    preflight_error(format!(
                        "workspace symlink target {} at {} has no exact Git object identity",
                        target_blob, artifact.path
                    ))
                })?,
                tree_entry: artifact.entry,
            },
            TreeEntry::Gitlink { target } => ExpectedIndexEntry {
                mode: gix::index::entry::Mode::COMMIT,
                oid: target,
                tree_entry: artifact.entry,
            },
        };
        if expected.insert(artifact.path.clone(), entry).is_some() {
            return Err(preflight_error(format!(
                "workspace seed repeats path {}",
                artifact.path
            )));
        }
    }
    Ok(expected)
}

fn read_strict_index(
    repo: &gix::Repository,
    absent_allowed: bool,
) -> Result<(gix::index::File, Option<Vec<u8>>)> {
    if repo.config_snapshot().boolean("core.sparseCheckout") == Some(true)
        || repo.git_dir().join("info/sparse-checkout").exists()
    {
        return Err(preflight_error(
            "sparse checkout configuration is ambiguous for exact migration",
        ));
    }
    let index_path = repo.index_path();
    let before = match fs::symlink_metadata(&index_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(preflight_error("Git index path is not a regular file"));
            }
            Some(fs::read(&index_path).map_err(|error| GitError::io(&index_path, error))?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && absent_allowed => None,
        Err(error) => return Err(GitError::io(&index_path, error)),
    };
    let index = gix::index::File::at_or_default(
        &index_path,
        repo.object_hash(),
        false,
        gix::index::decode::Options::default(),
    )
    .map_err(|error| preflight_error(format!("open strict Git index: {error}")))?;
    index
        .verify_entries()
        .map_err(|error| preflight_error(format!("verify Git index entries: {error}")))?;
    match &before {
        Some(before) => {
            let after = fs::read(&index_path).map_err(|error| GitError::io(&index_path, error))?;
            if before != &after {
                return Err(preflight_error(
                    "Git index changed while it was being verified",
                ));
            }
        }
        None => match fs::symlink_metadata(&index_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(preflight_error(
                    "previously absent Git index appeared while it was being verified",
                ));
            }
            Err(error) => return Err(GitError::io(&index_path, error)),
        },
    }
    Ok((index, before))
}

/// Observe the index against the committed workspace seed.
///
/// An entry that is not the committed one is staged work, which is recorded
/// rather than refused. What still refuses is an index that cannot be read as a
/// statement about the worktree at all: a conflict stage, a sparse directory
/// entry, and the two flags with which Git is told to stop comparing a path, so
/// a repository whose index disagrees with its own worktree by instruction is
/// never observed as if it agreed. `INTENT_TO_ADD` is not among them, because
/// it announces a path the operator has not committed, which is staged work
/// like any other.
fn prove_index(
    index: &gix::index::File,
    raw_file: Option<&[u8]>,
    expected: &BTreeMap<RepoPath, ExpectedIndexEntry>,
    divergence: &mut DivergenceLog,
) -> Result<GitIndexPreflightProof> {
    if index.is_sparse() {
        return Err(preflight_error(
            "sparse Git indexes cannot establish an exact materialized workspace",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut logical = FramedHash::new(b"kin.git.preflight.index.v1");
    logical.u64(index.entries().len() as u64);
    for entry in index.entries() {
        let path = RepoPath::from_bytes(entry.path(index).to_vec())
            .map_err(|error| preflight_error(format!("invalid index path: {error}")))?;
        if entry.stage() != gix::index::entry::Stage::Unconflicted {
            return Err(preflight_error(format!(
                "index path {path} has conflict stage {:?}",
                entry.stage()
            )));
        }
        let ambiguous = gix::index::entry::Flags::ASSUME_VALID
            | gix::index::entry::Flags::SKIP_WORKTREE
            | gix::index::entry::Flags::CONFLICTED;
        if entry.flags.intersects(ambiguous) {
            return Err(preflight_error(format!(
                "index path {path} has ambiguous flags {:?}",
                entry.flags & ambiguous
            )));
        }
        if entry.mode == gix::index::entry::Mode::DIR || entry.mode.is_sparse() {
            return Err(preflight_error(format!(
                "index path {path} is a sparse directory entry"
            )));
        }
        let actual_oid = git_object_id(entry.id)?;
        match expected.get(&path) {
            None => divergence.record(
                path.clone(),
                GitWorkspaceDivergenceKind::Staged,
                "the committed tree does not carry this path",
                None,
            ),
            Some(expected_entry)
                if entry.mode != expected_entry.mode || actual_oid != expected_entry.oid =>
            {
                divergence.record(
                    path.clone(),
                    GitWorkspaceDivergenceKind::Staged,
                    "the index entry is not the committed one",
                    None,
                )
            }
            Some(_) => {}
        }
        if !seen.insert(path.clone()) {
            return Err(preflight_error(format!("index repeats path {path}")));
        }
        logical.bytes(path.as_bytes());
        logical.u64(u64::from(entry.mode.bits()));
        logical.bytes(actual_oid.as_bytes());
        logical.u64(u64::from(entry.flags.bits()));
    }
    for path in expected.keys().filter(|path| !seen.contains(*path)) {
        divergence.record(
            path.clone(),
            GitWorkspaceDivergenceKind::StagedRemoval,
            "",
            None,
        );
    }
    Ok(GitIndexPreflightProof {
        present: raw_file.is_some(),
        at_rest_checksum: index.checksum().map(git_object_id).transpose()?,
        raw_file_hash: raw_file
            .map(digest)
            .unwrap_or_else(|| digest(b"kin.git.preflight.index.absent.v1")),
        logical_fingerprint: logical.finish(),
        entry_count: index.entries().len(),
        sparse: false,
    })
}

fn prove_worktree(
    ignore_repo: &gix::Repository,
    index: &gix::index::File,
    workdir: &Path,
    expected: &BTreeMap<RepoPath, ExpectedIndexEntry>,
    blob_store: &BlobStore,
    published_kin_dir: Option<&Path>,
    divergence: &mut DivergenceLog,
) -> Result<(GitTrackedWorktreeProof, IgnoredLocalWorktreeFact)> {
    let ignore_inputs = local_ignore_inputs(ignore_repo)?;
    let (mut excludes, ignore_case) = frozen_ignore_stack(ignore_repo, index, &ignore_inputs)?;
    let (executable_authority, symlink_materialization) = worktree_materialization(ignore_repo)?;
    let mut tracked_hash = FramedHash::new(b"kin.git.preflight.worktree.v2");
    tracked_hash.u64(expected.len() as u64);
    let indexed = index
        .entries()
        .iter()
        .map(|entry| entry.path(index).to_vec())
        .collect::<BTreeSet<_>>();
    let mut state = WorktreeWalk {
        expected,
        indexed: &indexed,
        blob_store,
        seen: BTreeSet::new(),
        tracked_hash,
        gitlink_count: 0,
        host_unrepresentable_count: 0,
        ignored: Vec::new(),
        executable_authority,
        symlink_materialization,
        diagnosis: Some(CheckoutDiagnosis {
            repo: ignore_repo,
            index,
        }),
        divergence,
    };
    let graph_only_paths = expected
        .iter()
        .filter(|(path, _)| !host_can_materialize_repo_path(path))
        .map(|(path, entry)| (path.clone(), *entry))
        .collect::<Vec<_>>();
    for (path, entry) in &graph_only_paths {
        if !state.seen.insert(path.clone()) {
            return Err(preflight_error(format!(
                "worktree graph-only proof repeats path {path}"
            )));
        }
        state.host_unrepresentable_count += 1;
        if matches!(entry.tree_entry, TreeEntry::Gitlink { .. }) {
            state.gitlink_count += 1;
        }
    }
    walk_directory(
        workdir,
        &[],
        true,
        published_kin_dir,
        &mut excludes,
        &mut state,
    )?;
    let confirmed_local_ignore_inputs = local_ignore_inputs(ignore_repo)?;
    if confirmed_local_ignore_inputs != ignore_inputs {
        return Err(preflight_error(
            "local Git ignore inputs changed while the worktree was being verified",
        ));
    }
    for path in expected.keys().filter(|path| !state.seen.contains(*path)) {
        state
            .divergence
            .record(path.clone(), GitWorkspaceDivergenceKind::Missing, "", None);
    }
    for (path, entry) in &graph_only_paths {
        hash_host_unrepresentable_entry(&mut state.tracked_hash, path, entry.tree_entry);
    }
    state
        .ignored
        .sort_by(|left, right| left.path.cmp(&right.path));
    let mut ignored_hash = FramedHash::new(b"kin.git.preflight.ignored.v1");
    ignored_hash.u64(u64::from(ignore_case));
    ignored_hash.u64(ignore_inputs.len() as u64);
    for input in &ignore_inputs {
        ignored_hash.u64(local_ignore_source_code(input.source_kind));
        ignored_hash.u64(input.order as u64);
        ignored_hash.bytes(input.body_hash.as_bytes());
        ignored_hash.u64(input.body_len);
        ignored_hash.bytes(&input.body);
    }
    ignored_hash.u64(state.ignored.len() as u64);
    for entry in &state.ignored {
        ignored_hash.bytes(entry.path.as_bytes());
        ignored_hash.u64(ignored_kind_code(entry.kind));
        ignored_hash.u64(entry.byte_len);
    }
    Ok((
        GitTrackedWorktreeProof {
            entry_count: state.seen.len(),
            gitlink_count: state.gitlink_count,
            host_unrepresentable_count: state.host_unrepresentable_count,
            fingerprint: state.tracked_hash.finish(),
        },
        IgnoredLocalWorktreeFact {
            inputs: ignore_inputs,
            ignore_case,
            entries: state.ignored,
            fingerprint: ignored_hash.finish(),
        },
    ))
}

struct WorktreeWalk<'a> {
    expected: &'a BTreeMap<RepoPath, ExpectedIndexEntry>,
    /// Every path the index carries, which is what Git means by tracked. A path
    /// here but not in `expected` is staged work, already reported as such by
    /// the index observation, so the walk neither repeats it as untracked nor
    /// records it as ignored local content.
    indexed: &'a BTreeSet<Vec<u8>>,
    blob_store: &'a BlobStore,
    seen: BTreeSet<RepoPath>,
    tracked_hash: FramedHash,
    gitlink_count: usize,
    host_unrepresentable_count: usize,
    ignored: Vec<IgnoredLocalEntry>,
    executable_authority: ExecutableModeAuthority,
    symlink_materialization: SymlinkMaterialization,
    /// Absent when a caller has no repository to consult, which costs only the
    /// precision of a report and never changes whether one is raised.
    diagnosis: Option<CheckoutDiagnosis<'a>>,
    divergence: &'a mut DivergenceLog,
}

/// Read-only Git handles consulted solely to explain a refusal.
///
/// Nothing reached through here answers a preflight question. The lookup runs
/// only after a byte comparison has already failed, and only to name the
/// transformation that produced the worktree bytes, so a repository Git itself
/// rewrites on checkout is never reported as carrying an edit its operator
/// never made.
#[derive(Clone, Copy)]
struct CheckoutDiagnosis<'a> {
    repo: &'a gix::Repository,
    index: &'a gix::index::File,
}

/// Why one tracked blob's worktree bytes disagree with the committed tree.
enum BlobDivergence {
    /// Git rewrote the bytes on checkout, so the worktree holds exactly what a
    /// clean checkout of this commit produces.
    CheckoutTransformation(String),
    /// Nothing Git does on checkout accounts for the bytes, so the worktree
    /// carries a real edit.
    UnstagedEdit,
}

/// The `.gitattributes` assignments that let Git rewrite one path on checkout.
///
/// Line-ending assignments are kept apart from the rest because they explain
/// exactly one shape of difference. Treating them as a blanket excuse would
/// reintroduce the conflation in the other direction, reporting a genuine edit
/// to a normalized file as a filter.
#[derive(Default)]
struct CheckoutAttributes {
    /// Assignments that normalize line endings and change nothing else.
    line_ending: Vec<String>,
    /// The first assignment that may rewrite the bytes arbitrarily.
    rewriting: Option<String>,
}

/// Byte prefix every Git LFS pointer blob begins with.
const LFS_POINTER_PREFIX: &[u8] = b"version https://git-lfs.github.com/spec/";

/// Name the checkout transformation behind diverging bytes, or report an edit.
///
/// The order is deliberate. Line-ending normalization is established from the
/// bytes themselves rather than from the attribute, so a real edit to a file
/// marked `text` still reads as an edit. An attribute that can rewrite content
/// arbitrarily is the only one allowed to explain a difference the bytes do not.
fn classify_blob_divergence(
    diagnosis: Option<CheckoutDiagnosis<'_>>,
    path: &RepoPath,
    worktree: &[u8],
    committed: &[u8],
) -> BlobDivergence {
    if committed.starts_with(LFS_POINTER_PREFIX) && !worktree.starts_with(LFS_POINTER_PREFIX) {
        return BlobDivergence::CheckoutTransformation(
            "Git LFS smudges it, so the committed tree holds a pointer where the worktree \
             holds the file's content"
                .to_string(),
        );
    }
    let attributes = diagnosis
        .map(|diagnosis| checkout_attributes(diagnosis, path))
        .unwrap_or_default();
    if line_endings_only(worktree, committed) {
        return BlobDivergence::CheckoutTransformation(if attributes.line_ending.is_empty() {
            "Git normalizes its line endings on checkout".to_string()
        } else {
            format!(
                ".gitattributes marks it {}, so Git normalizes its line endings on checkout",
                attributes.line_ending.join(" ")
            )
        });
    }
    match attributes.rewriting {
        Some(assignment) => BlobDivergence::CheckoutTransformation(format!(
            ".gitattributes marks it {assignment}, so Git rewrites it on checkout"
        )),
        None => BlobDivergence::UnstagedEdit,
    }
}

/// Read the checkout-rewriting attributes Git resolves for one path.
///
/// Attributes come from the committed index mapping, the same source the rest
/// of this preflight trusts, so explaining a refusal never reads an ambient
/// `.gitattributes` off the filesystem. A lookup that cannot be completed
/// yields no attributes and the refusal falls back to what the bytes prove.
fn checkout_attributes(diagnosis: CheckoutDiagnosis<'_>, path: &RepoPath) -> CheckoutAttributes {
    let mut found = CheckoutAttributes::default();
    let Ok(mut stack) = diagnosis.repo.attributes_only(
        diagnosis.index,
        gix::worktree::stack::state::attributes::Source::IdMapping,
    ) else {
        return found;
    };
    let Ok(platform) = stack.at_entry(
        path.as_bytes().as_bstr(),
        Some(gix::index::entry::Mode::FILE),
    ) else {
        return found;
    };
    let mut outcome = gix::attrs::search::Outcome::default();
    if !platform.matching_attributes(&mut outcome) {
        return found;
    }
    for matched in outcome.iter() {
        let assignment = matched.assignment;
        // `-text` and `!text` disable the transformation rather than request
        // it, so only a set or valued assignment explains rewritten bytes.
        if !matches!(
            assignment.state,
            gix::attrs::StateRef::Set | gix::attrs::StateRef::Value(_)
        ) {
            continue;
        }
        match assignment.name.as_str() {
            "text" | "eol" => found.line_ending.push(assignment.to_string()),
            "filter" | "working-tree-encoding" | "ident" => {
                if found.rewriting.is_none() {
                    found.rewriting = Some(assignment.to_string());
                }
            }
            _ => {}
        }
    }
    found
}

/// Whether two blobs carry the same content and differ only in line endings.
fn line_endings_only(left: &[u8], right: &[u8]) -> bool {
    without_carriage_returns(left) == without_carriage_returns(right)
}

/// Drop the carriage return of every CRLF pair, leaving lone returns in place.
fn without_carriage_returns(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            index += 1;
            continue;
        }
        normalized.push(bytes[index]);
        index += 1;
    }
    normalized
}

/// Where the exact executable bit of a tracked blob is read from.
///
/// Git resolves this the same way: a worktree whose filesystem carries the bit
/// is compared against it, and one that does not is trusted to the index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutableModeAuthority {
    /// The worktree filesystem records the bit, so the materialized file is
    /// compared against the committed mode directly.
    WorktreeMode,
    /// The filesystem records no executable bit, so the index carries the
    /// exact mode. `prove_index` already proved every index entry's mode
    /// equals its committed tree entry, so no worktree comparison remains.
    IndexMode,
}

/// How a tracked symbolic link is materialized in the worktree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SymlinkMaterialization {
    /// The worktree carries a real symbolic link.
    Link,
    /// Git materializes a tracked symlink as a regular file whose bytes are
    /// the link target, because this worktree cannot hold real links.
    TargetTextFile(SymlinkCapabilitySource),
}

/// Who decided that a tracked symlink is materialized as target text.
///
/// A repository that recorded `core.symlinks=false` stated something; one that
/// recorded nothing stated nothing and had a platform default applied to it.
/// Both end at the same materialization, and a refusal that blames the
/// repository for a value it never wrote is describing the wrong party. This
/// is the same distinction [`LocalGitHookExecutability`] draws between an
/// observation and its absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SymlinkCapabilitySource {
    /// The repository recorded `core.symlinks=false`.
    RepositoryRecorded,
    /// The repository recorded no value, so Git's compiled-in default for this
    /// platform decides.
    PlatformDefault,
}

/// Resolve how this host and repository materialize modes and symbolic links.
///
/// A host whose filesystem carries the executable bit also carries real
/// symbolic links, and the worktree is the exact authority for both. Nothing
/// is read from configuration there, so a repository-local `core.fileMode` or
/// `core.symlinks` override cannot change what an already materialized
/// checkout physically holds.
///
/// A host whose filesystem carries neither is Windows. `core.fileMode=true`
/// asks Git to compare against a mode it synthesizes from the file name or a
/// `#!` prefix, which is not a byte-exact observation of anything and is
/// refused rather than admitted as proof. `core.symlinks` decides the other
/// half: Git for Windows probes the symlink privilege when it creates a
/// repository and records the result, and its compiled-in default without a
/// recorded value is off, which materializes a tracked symlink as a regular
/// file holding the target text.
///
/// Both arms live in one body so every variant stays constructed on every
/// target and the platform difference reads as one decision.
fn worktree_materialization(
    repo: &gix::Repository,
) -> Result<(ExecutableModeAuthority, SymlinkMaterialization)> {
    if filesystem_records_executable_bit() {
        return Ok((
            ExecutableModeAuthority::WorktreeMode,
            SymlinkMaterialization::Link,
        ));
    }
    let config = repo.config_snapshot();
    if config.boolean("core.fileMode") == Some(true) {
        return Err(preflight_error(
            "repository sets core.fileMode=true, but this platform's filesystem records no \
             executable bit; Git would compare a mode synthesized from the file name or a `#!` \
             prefix, which proves nothing byte-exact. Set core.fileMode=false, the value Git \
             records for a repository created on this platform, so the index carries the exact \
             mode",
        ));
    }
    let materialization = match config.boolean("core.symlinks") {
        Some(true) => SymlinkMaterialization::Link,
        Some(false) => {
            SymlinkMaterialization::TargetTextFile(SymlinkCapabilitySource::RepositoryRecorded)
        }
        // `boolean` answers `None` both for a key that is absent and for one
        // holding a value Git cannot read as a boolean. Those are different
        // repository states and only the first has a defensible default, so a
        // recorded value that is not a boolean is refused by name rather than
        // silently resolving to off.
        None => match config.string("core.symlinks") {
            Some(recorded) => {
                return Err(preflight_error(format!(
                    "repository records core.symlinks={recorded:?}, which Git cannot resolve as a \
                     boolean, so whether this worktree holds real symbolic links or the target \
                     text Git writes in their place is unstated. Record true or false"
                )));
            }
            None => {
                SymlinkMaterialization::TargetTextFile(SymlinkCapabilitySource::PlatformDefault)
            }
        },
    };
    Ok((ExecutableModeAuthority::IndexMode, materialization))
}

fn host_can_materialize_repo_path(path: &RepoPath) -> bool {
    if path.as_utf8().is_none() {
        #[cfg(any(windows, target_os = "macos"))]
        return false;
    }
    true
}

fn hash_host_unrepresentable_entry(hash: &mut FramedHash, path: &RepoPath, entry: TreeEntry) {
    hash.bytes(path.as_bytes());
    // Representation code 4 is deliberately distinct from materialized blob,
    // symlink, and Gitlink codes 1-3 below.
    hash.u64(4);
    match entry {
        TreeEntry::Blob {
            hash: blob,
            executable,
        } => {
            hash.u64(1);
            hash.bytes(blob.as_bytes());
            hash.u64(u64::from(executable));
        }
        TreeEntry::Symlink { target_blob } => {
            hash.u64(2);
            hash.bytes(target_blob.as_bytes());
        }
        TreeEntry::Gitlink { target } => {
            hash.u64(3);
            hash.bytes(target.as_bytes());
        }
    }
}

fn walk_directory(
    absolute: &Path,
    relative: &[u8],
    root: bool,
    published_kin_dir: Option<&Path>,
    excludes: &mut gix::AttributeStack<'_>,
    state: &mut WorktreeWalk<'_>,
) -> Result<()> {
    let entries = fs::read_dir(absolute)
        .map_err(|error| GitError::io(absolute, error))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| GitError::io(absolute, error))?;
    // Names are resolved before ordering so a name this host cannot represent
    // exactly fails the walk rather than sorting under a repaired substitute.
    let entries = exact_directory_names(absolute, entries)?;

    for (name, directory_entry) in entries {
        if root && name == b".git" {
            continue;
        }
        let absolute_path = directory_entry.path();
        if root && published_kin_dir.is_some_and(|published| absolute_path == published) {
            continue;
        }
        let path_bytes = if relative.is_empty() {
            name
        } else {
            let mut joined = Vec::with_capacity(relative.len() + 1 + name.len());
            joined.extend_from_slice(relative);
            joined.push(b'/');
            joined.extend_from_slice(&name);
            joined
        };
        let path = RepoPath::from_bytes(path_bytes.clone())
            .map_err(|error| preflight_error(format!("invalid worktree path: {error}")))?;
        let metadata = fs::symlink_metadata(&absolute_path)
            .map_err(|error| GitError::io(&absolute_path, error))?;

        if let Some(expected) = state.expected.get(&path).copied() {
            prove_tracked_entry(&absolute_path, &path, &metadata, expected, state)?;
            continue;
        }
        if state.indexed.contains(&path_bytes) {
            continue;
        }

        let mode = if metadata.is_dir() {
            Some(gix::index::entry::Mode::DIR)
        } else if metadata.file_type().is_symlink() {
            Some(gix::index::entry::Mode::SYMLINK)
        } else {
            Some(gix::index::entry::Mode::FILE)
        };
        let ignored = excludes
            .at_entry(path_bytes.as_bstr(), mode)
            .map_err(|error| preflight_error(format!("evaluate ignore rules for {path}: {error}")))?
            .is_excluded();
        if metadata.is_dir() {
            if ignored {
                state.ignored.push(IgnoredLocalEntry {
                    path: path.clone(),
                    kind: IgnoredLocalEntryKind::Directory,
                    byte_len: 0,
                });
            }
            walk_directory(
                &absolute_path,
                &path_bytes,
                false,
                published_kin_dir,
                excludes,
                state,
            )?;
        } else if ignored {
            state.ignored.push(IgnoredLocalEntry {
                path,
                kind: ignored_entry_kind(&metadata),
                byte_len: metadata.len(),
            });
        } else {
            state.divergence.record_untracked(path);
        }
    }
    Ok(())
}

/// Record one tracked leaf as materialized differently than committed.
///
/// The tracked fingerprint carries a marker rather than the committed identity,
/// so a worktree that diverges never fingerprints as one that matched. What
/// differs is carried by the divergence facts, which the marker deliberately
/// does not repeat.
fn diverged(
    state: &mut WorktreeWalk<'_>,
    path: &RepoPath,
    detail: impl Into<String>,
    observed: Option<Hash256>,
) {
    state.tracked_hash.u64(5);
    state.divergence.record(
        path.clone(),
        GitWorkspaceDivergenceKind::Modified,
        detail,
        observed,
    );
}

/// Observe one tracked leaf against its committed entry.
///
/// A leaf the worktree materializes differently is recorded and the walk
/// continues, because the committed entry is authority and the worktree is
/// workspace state. A materialized nested repository still refuses: its content
/// belongs to another repository, and admitting it as this workspace's edits
/// would swallow a checkout Kin never mapped.
fn prove_tracked_entry(
    absolute_path: &Path,
    path: &RepoPath,
    metadata: &fs::Metadata,
    expected: ExpectedIndexEntry,
    state: &mut WorktreeWalk<'_>,
) -> Result<()> {
    if !state.seen.insert(path.clone()) {
        return Err(preflight_error(format!(
            "worktree materializes tracked path {path} more than once"
        )));
    }
    state.tracked_hash.bytes(path.as_bytes());
    match expected.tree_entry {
        TreeEntry::Blob { hash, executable } => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                diverged(
                    state,
                    path,
                    "the worktree no longer materializes it as a regular file",
                    None,
                );
                return Ok(());
            }
            if state.executable_authority == ExecutableModeAuthority::WorktreeMode
                && filesystem_executable(metadata)? != executable
            {
                diverged(
                    state,
                    path,
                    "its executable mode differs from the committed tree",
                    None,
                );
                return Ok(());
            }
            let actual =
                fs::read(absolute_path).map_err(|error| GitError::io(absolute_path, error))?;
            let committed = state.blob_store.read(&hash)?;
            if actual != committed {
                let detail =
                    match classify_blob_divergence(state.diagnosis, path, &actual, &committed) {
                        BlobDivergence::CheckoutTransformation(reason) => format!(
                            "its worktree bytes differ from the committed tree because {reason}, \
                             so this is not an unstaged edit"
                        ),
                        BlobDivergence::UnstagedEdit => "its worktree bytes differ from the \
                             committed tree and no checkout filter, LFS pointer, or line-ending \
                             normalization explains the difference"
                            .to_string(),
                    };
                diverged(state, path, detail, Some(digest(&actual)));
                return Ok(());
            }
            state.tracked_hash.u64(1);
            state.tracked_hash.bytes(hash.as_bytes());
            state.tracked_hash.u64(u64::from(executable));
        }
        TreeEntry::Symlink { target_blob } => {
            let target = match state.symlink_materialization {
                SymlinkMaterialization::Link => {
                    if !metadata.file_type().is_symlink() {
                        diverged(
                            state,
                            path,
                            "the worktree no longer materializes it as a symbolic link",
                            None,
                        );
                        return Ok(());
                    }
                    let target = fs::read_link(absolute_path)
                        .map_err(|error| GitError::io(absolute_path, error))?;
                    path_bytes(&target)?
                }
                // Git materializes a tracked symlink as a regular file holding
                // the target text when it cannot create links, and compares
                // that file's bytes against the committed target blob. Reading
                // those bytes is the same observation Git makes, not a
                // filesystem fallback for a missing link.
                SymlinkMaterialization::TargetTextFile(source) => {
                    if metadata.file_type().is_symlink() {
                        diverged(
                            state,
                            path,
                            match source {
                                SymlinkCapabilitySource::RepositoryRecorded => {
                                    "it is a real symbolic link, but the repository records \
                                     core.symlinks=false, so Git writes and compares the target \
                                     as a regular file here"
                                }
                                SymlinkCapabilitySource::PlatformDefault => {
                                    "it is a real symbolic link, but this repository records no \
                                     core.symlinks value and Git's default on this platform \
                                     writes and compares the target as a regular file. Record \
                                     core.symlinks=true if this worktree really does carry real \
                                     links"
                                }
                            },
                            None,
                        );
                        return Ok(());
                    }
                    if !metadata.is_file() {
                        diverged(
                            state,
                            path,
                            "it is not the regular file holding its target, which is what Git \
                             materializes under core.symlinks=off",
                            None,
                        );
                        return Ok(());
                    }
                    fs::read(absolute_path).map_err(|error| GitError::io(absolute_path, error))?
                }
            };
            let committed = state.blob_store.read(&target_blob)?;
            if target != committed {
                diverged(
                    state,
                    path,
                    "its link target differs from the committed tree",
                    Some(digest(&target)),
                );
                return Ok(());
            }
            state.tracked_hash.u64(2);
            state.tracked_hash.bytes(target_blob.as_bytes());
        }
        TreeEntry::Gitlink { target } => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                diverged(
                    state,
                    path,
                    "the worktree no longer materializes it as a directory",
                    None,
                );
                return Ok(());
            }
            let mut entries =
                fs::read_dir(absolute_path).map_err(|error| GitError::io(absolute_path, error))?;
            if entries
                .next()
                .transpose()
                .map_err(|error| GitError::io(absolute_path, error))?
                .is_some()
            {
                return Err(preflight_error(format!(
                    "gitlink {path} has materialized nested-repository state; exact graph-native nested repository mapping is required before migration"
                )));
            }
            state.gitlink_count += 1;
            state.tracked_hash.u64(3);
            state.tracked_hash.bytes(target.as_bytes());
            // An empty placeholder is only the worktree representation of the
            // graph-owned pointer. Any nested state above fails closed.
        }
    }
    Ok(())
}

pub(crate) fn reject_in_progress_operations(repo: &gix::Repository) -> Result<()> {
    if let Some(operation) = repo.state() {
        return Err(preflight_error(format!(
            "Git operation {operation:?} is in progress"
        )));
    }
    let mut roots = vec![repo.git_dir().to_path_buf()];
    if stable_path(repo.common_dir()) != stable_path(repo.git_dir()) {
        roots.push(repo.common_dir().to_path_buf());
    }
    for root in &roots {
        if let Some(reason) = in_progress_operation_state(root)? {
            return Err(preflight_error(reason));
        }
    }
    Ok(())
}

/// Administrative state under one Git directory that says work is unfinished.
///
/// Split out of [`reject_in_progress_operations`] because a sibling worktree
/// keeps its own copy of every one of these under `.git/worktrees/<id>`, which
/// neither the source's Git directory nor the common directory contains. Asking
/// this of the source alone leaves a sibling mid-rebase invisible.
fn in_progress_operation_state(root: &Path) -> Result<Option<String>> {
    const MARKERS: &[&str] = &[
        "rebase-apply",
        "rebase-merge",
        "sequencer",
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "REBASE_HEAD",
        "BISECT_LOG",
        "BISECT_START",
        "index.lock",
        "HEAD.lock",
        "packed-refs.lock",
        "shallow.lock",
        "config.lock",
        "gc.pid",
    ];
    for marker in MARKERS {
        let path = root.join(marker);
        if fs::symlink_metadata(&path).is_ok() {
            return Ok(Some(format!(
                "Git administrative state {} indicates an in-progress or incomplete operation",
                path.display()
            )));
        }
    }
    for relative in ["refs", "logs", "reftable", "objects/pack", "objects/info"] {
        if let Some(lock) = find_lock_file(&root.join(relative))? {
            return Ok(Some(format!(
                "Git lock {} indicates concurrent repository mutation",
                lock.display()
            )));
        }
    }
    Ok(None)
}

fn find_lock_file(root: &Path) -> Result<Option<PathBuf>> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(GitError::io(root, error)),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(None);
    }
    let entries = fs::read_dir(root)
        .map_err(|error| GitError::io(root, error))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| GitError::io(root, error))?;
    let entries = exact_directory_names(root, entries)?;
    for (name, entry) in entries {
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| GitError::io(entry.path(), error))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if let Some(lock) = find_lock_file(&entry.path())? {
                return Ok(Some(lock));
            }
        } else if name.ends_with(b".lock") {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

pub(crate) fn other_registered_worktrees(
    repo: &gix::Repository,
    source_worktree: &Path,
) -> Result<Vec<RegisteredGitWorktreeFact>> {
    let current_git_dir = stable_path(repo.git_dir());
    let mut facts = Vec::new();
    let main = repo
        .main_repo()
        .map_err(|error| preflight_error(format!("open main Git repository: {error}")))?;
    if !main.is_bare() {
        if let Some(workdir) = main.workdir() {
            if stable_path(workdir) != stable_path(source_worktree)
                && stable_path(main.git_dir()) != current_git_dir
            {
                facts.push(RegisteredGitWorktreeFact {
                    kind: RegisteredGitWorktreeKind::Main,
                    id: None,
                    path: workdir.to_path_buf(),
                    git_dir: main.git_dir().to_path_buf(),
                    locked: false,
                });
            }
        }
    }
    for proxy in repo
        .worktrees()
        .map_err(|error| preflight_error(format!("enumerate linked Git worktrees: {error}")))?
    {
        if stable_path(proxy.git_dir()) == current_git_dir {
            continue;
        }
        let path = proxy.base().map_err(|error| {
            preflight_error(format!(
                "read linked worktree {} location: {error}",
                proxy.id()
            ))
        })?;
        facts.push(RegisteredGitWorktreeFact {
            kind: RegisteredGitWorktreeKind::Linked,
            id: Some(proxy.id().to_vec()),
            path,
            git_dir: proxy.git_dir().to_path_buf(),
            locked: proxy.is_locked(),
        });
    }
    facts.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(facts)
}

/// Split the other registered worktrees into the ones this migration can
/// tolerate and the ones it cannot, with a reason for each refusal.
///
/// A worktree sharing the object database is not itself a problem. What the
/// capture needs is that every object the migration must carry is reachable
/// from a ref the capture reads, and that nothing is mutating the database
/// while it reads. Both are decidable from the sibling's own Git directory.
///
/// The capture walks [`crate::lossless::capture_lossless_git_repository`],
/// which iterates the source worktree's reference store and its own HEAD.
/// That store publishes the shared refs plus the source's private ones. A
/// sibling's HEAD lives in `.git/worktrees/<id>/HEAD` and its per-worktree refs
/// in `.git/worktrees/<id>/refs`, and neither is published there. So a sibling
/// checked out on an ordinary shared branch names nothing the capture misses:
/// its commits arrive through `refs/heads/<branch>` like any other. A sibling
/// at a detached HEAD, or holding its own refs, can anchor commits no shared
/// ref reaches, and migrating away from that object database would drop them.
///
/// Concurrency needs no rule here. The capture re-reads refs and HEAD after
/// walking the object closure, and [`preflight_git_migration`] observes the
/// source twice and compares, so a commit made in any worktree during the proof
/// is caught as source drift whichever worktree made it.
///
/// What a tolerated sibling still costs is disclosed rather than refused: its
/// commits are admitted, its uncommitted work is not, and Kin creates no
/// workspace for it.
pub(crate) fn classify_other_worktrees(
    repo: &gix::Repository,
    worktrees: Vec<RegisteredGitWorktreeFact>,
) -> Result<(Vec<RegisteredGitWorktreeFact>, Vec<UntolerableGitWorktree>)> {
    let mut tolerated = Vec::new();
    let mut untolerable = Vec::new();
    for worktree in worktrees {
        match untolerable_worktree_state(repo, &worktree)? {
            Some((reason, remedy)) => untolerable.push(UntolerableGitWorktree {
                worktree,
                reason,
                remedy,
            }),
            None => tolerated.push(worktree),
        }
    }
    Ok((tolerated, untolerable))
}

/// Why one sibling worktree cannot be tolerated, if it cannot.
fn untolerable_worktree_state(
    repo: &gix::Repository,
    worktree: &RegisteredGitWorktreeFact,
) -> Result<Option<(String, String)>> {
    let git_dir = &worktree.git_dir;
    // A reftable worktree keeps its refs in a format this boundary does not
    // read, so nothing below can tell a private ref from an empty store.
    if fs::symlink_metadata(git_dir.join("reftable")).is_ok() {
        return Ok(Some((
            "keeps its refs in a reftable this boundary cannot read, so whether it anchors \
             commits no shared ref names is undecidable"
                .to_string(),
            "remove it with 'git worktree remove', then run kin init again".to_string(),
        )));
    }
    if let Some(reason) = in_progress_operation_state(git_dir)? {
        return Ok(Some((
            format!("has an operation still running against this object database: {reason}"),
            "finish or abort that worktree's Git operation, then run kin init again".to_string(),
        )));
    }
    // Which namespaces count as private depends on which git dir this is. A
    // linked sibling's git dir holds only per-worktree refs, so everything
    // loose under it is private. The main worktree's git dir IS the shared
    // store, so walking its whole refs tree would misread every loose branch
    // as private; only bisect and worktree refs belong to that checkout alone.
    let private = match worktree.kind {
        RegisteredGitWorktreeKind::Linked => first_private_worktree_ref(git_dir)?,
        RegisteredGitWorktreeKind::Main => first_private_main_worktree_ref(git_dir)?,
    };
    if let Some(private) = private {
        return Ok(Some((
            format!(
                "carries its own ref {}, which this repository's shared reference store does not \
                 publish, so the capture cannot see what it anchors",
                private.display()
            ),
            "clear that worktree's per-worktree refs, for example with 'git bisect reset'"
                .to_string(),
        )));
    }
    match read_worktree_head(git_dir)? {
        WorktreeHead::Detached => Ok(Some((
            "is checked out at a detached HEAD, which no shared ref names, so the capture cannot \
             prove it carries that worktree's commits"
                .to_string(),
            "check that worktree out on a branch, or remove it with 'git worktree remove'"
                .to_string(),
        ))),
        WorktreeHead::Branch(name) => {
            if shared_branch_exists(repo, &name) {
                Ok(None)
            } else {
                Ok(Some((
                    format!(
                        "is on branch {}, which this repository's shared reference store does not \
                         carry, so the capture cannot reach what it points at",
                        String::from_utf8_lossy(&name)
                    ),
                    "commit that branch, or remove the worktree with 'git worktree remove'"
                        .to_string(),
                )))
            }
        }
        WorktreeHead::Unreadable(detail) => Ok(Some((
            format!("has a HEAD this boundary cannot read: {detail}"),
            "remove it with 'git worktree remove', then run kin init again".to_string(),
        ))),
    }
}

/// What one worktree's own `HEAD` file says it is checked out at.
enum WorktreeHead {
    /// Symbolic at a full ref name.
    Branch(Vec<u8>),
    /// Directly at an object.
    Detached,
    Unreadable(String),
}

fn read_worktree_head(git_dir: &Path) -> Result<WorktreeHead> {
    let path = git_dir.join("HEAD");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WorktreeHead::Unreadable(format!(
                "{} is absent",
                path.display()
            )));
        }
        Err(error) => return Err(GitError::io(&path, error)),
    };
    let trimmed = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b'\n' | b'\r'))
        .map_or(&bytes[..0], |last| &bytes[..=last]);
    let Some(target) = trimmed.strip_prefix(b"ref: ") else {
        return Ok(WorktreeHead::Detached);
    };
    let target = target.strip_prefix(b" ").unwrap_or(target);
    if !target.starts_with(b"refs/") {
        return Ok(WorktreeHead::Unreadable(format!(
            "symbolic target {} is not a full ref name",
            String::from_utf8_lossy(target)
        )));
    }
    Ok(WorktreeHead::Branch(target.to_vec()))
}

/// Whether a branch the sibling names is one the capture's reference store
/// publishes.
///
/// Only `refs/heads/` counts. Every other namespace a symbolic HEAD could name
/// is either per-worktree, and therefore already refused above, or not a place
/// `git worktree add` puts a checkout.
fn shared_branch_exists(repo: &gix::Repository, name: &[u8]) -> bool {
    if !name.starts_with(b"refs/heads/") {
        return false;
    }
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    repo.find_reference(name).is_ok()
}

/// The first ref one linked worktree keeps privately, if it keeps any.
///
/// `.git/worktrees/<id>/refs` is where Git puts `refs/bisect/*` and
/// `refs/worktree/*`, which belong to that worktree alone. Packed refs are
/// always shared, so a loose walk here is the complete private set. Only a
/// linked sibling's git dir has this shape; the main worktree's git dir is
/// the shared store and goes through [`first_private_main_worktree_ref`].
fn first_private_worktree_ref(git_dir: &Path) -> Result<Option<PathBuf>> {
    first_loose_ref_under(&git_dir.join("refs"))
}

/// The first per-worktree ref the main worktree keeps, if it keeps any.
///
/// The main worktree's git dir is the shared reference store: `refs/heads/*`
/// under it are the repository's published branches, loose or packed by pack
/// state alone, so a whole-tree walk would refuse ordinary branches as
/// private and flip admission on packing. Git scopes exactly `refs/bisect/*`
/// and `refs/worktree/*` to the main checkout, so those are the complete
/// private set here.
fn first_private_main_worktree_ref(git_dir: &Path) -> Result<Option<PathBuf>> {
    for namespace in ["refs/bisect", "refs/worktree"] {
        if let Some(found) = first_loose_ref_under(&git_dir.join(namespace))? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn first_loose_ref_under(root: &Path) -> Result<Option<PathBuf>> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(GitError::io(root, error)),
    };
    let entries = entries
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| GitError::io(root, error))?;
    let mut paths = entries
        .into_iter()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        let metadata = fs::symlink_metadata(&path).map_err(|error| GitError::io(&path, error))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if let Some(found) = first_loose_ref_under(&path)? {
                return Ok(Some(found));
            }
        } else {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

pub(crate) fn checkout_filter_facts(repo: &gix::Repository) -> Vec<GitCheckoutFilterFact> {
    let config = repo.config_snapshot();
    let mut facts = BTreeMap::<Vec<u8>, GitCheckoutFilterFact>::new();
    if let Some(sections) = config.plumbing().sections_by_name("filter") {
        for section in sections {
            let Some(name) = section.header().subsection_name() else {
                continue;
            };
            let clean_present = section.contains_value_name("clean");
            let smudge_present = section.contains_value_name("smudge");
            let process_present = section.contains_value_name("process");
            if !clean_present && !smudge_present && !process_present {
                continue;
            }
            let fact = facts
                .entry(name.to_vec())
                .or_insert_with(|| GitCheckoutFilterFact {
                    name: name.to_vec(),
                    clean_present: false,
                    smudge_present: false,
                    process_present: false,
                    required_present: false,
                });
            fact.clean_present |= clean_present;
            fact.smudge_present |= smudge_present;
            fact.process_present |= process_present;
            fact.required_present |= section.contains_value_name("required");
        }
    }
    facts.into_values().collect()
}

/// Everything one repository-local Git configuration says about transport.
pub(crate) struct RemoteMappingScan {
    pub(crate) facts: GitRemoteMappingFacts,
    /// Every reason this configuration is outside the safe exact subset, in
    /// configuration order. Non-empty means `facts` is incomplete, because a
    /// section that carried a refusal contributed nothing.
    pub(crate) refusals: Vec<String>,
}

/// Read the transport configuration, refusing at the first reason it carries.
pub(crate) fn remote_mapping_facts(repo: &gix::Repository) -> Result<GitRemoteMappingFacts> {
    let scan = scan_remote_mapping(repo)?;
    match scan.refusals.into_iter().next() {
        Some(reason) => Err(unsafe_git_config(reason)),
        None => Ok(scan.facts),
    }
}

/// Read the transport configuration, collecting every reason it carries.
///
/// A repository whose configuration is outside the safe subset usually holds
/// more than one key that puts it there, and clearing them one refusal per run
/// is what makes a five-minute edit an afternoon. Only a configuration this
/// boundary cannot read at all still stops the scan, because past that point
/// the remaining sections are not decidable.
pub(crate) fn scan_remote_mapping(repo: &gix::Repository) -> Result<RemoteMappingScan> {
    let config = repo.config_snapshot();
    let mut remotes = Vec::<GitRemoteConfigFact>::new();
    let mut branch_tracking = Vec::<GitBranchTrackingFact>::new();
    let mut remote_push_default = None;
    let mut push_default = None;
    let mut push_auto_setup_remote = None;
    let mut refusals = Vec::<String>::new();

    for section in config.plumbing().sections().filter(|section| {
        matches!(
            section.meta().source,
            gix::config::Source::Local | gix::config::Source::Worktree
        )
    }) {
        let section_name = section
            .header()
            .name()
            .to_str()
            .map_err(|_| unsafe_git_config("non-UTF-8 section name"))?
            .to_ascii_lowercase();
        if section.meta().level != 0 || matches!(section_name.as_str(), "include" | "includeif") {
            refusals.push("repository-local include".to_string());
            continue;
        }

        match section_name.as_str() {
            "remote" => {
                if let Some(name) = section.header().subsection_name() {
                    validate_safe_identifier(name, "remote name")?;
                    if collect_unknown_config_keys(
                        section,
                        &format!("remote.{}", String::from_utf8_lossy(name)),
                        &["url", "pushurl", "fetch", "push"],
                        &[],
                        &mut refusals,
                    ) {
                        continue;
                    }
                    let fact = remote_fact_mut(&mut remotes, name);
                    append_explicit_values(
                        section,
                        "url",
                        &mut fact.fetch_urls,
                        validate_safe_remote_url,
                    )?;
                    append_explicit_values(
                        section,
                        "pushurl",
                        &mut fact.push_urls,
                        validate_safe_remote_url,
                    )?;
                    append_explicit_values(section, "fetch", &mut fact.fetch_refspecs, |value| {
                        validate_safe_refspec(value, gix::refspec::parse::Operation::Fetch)
                    })?;
                    append_explicit_values(section, "push", &mut fact.push_refspecs, |value| {
                        validate_safe_refspec(value, gix::refspec::parse::Operation::Push)
                    })?;
                } else {
                    if collect_unknown_config_keys(
                        section,
                        "remote",
                        &["pushdefault"],
                        &[],
                        &mut refusals,
                    ) {
                        continue;
                    }
                    set_unique_explicit_value(
                        section,
                        "pushdefault",
                        &mut remote_push_default,
                        |value| validate_safe_identifier(value, "remote.pushDefault"),
                    )?;
                }
            }
            "branch" => {
                let name = section
                    .header()
                    .subsection_name()
                    .ok_or_else(|| unsafe_git_config("branch section without a name"))?;
                validate_safe_branch_name(name)?;
                if collect_unknown_config_keys(
                    section,
                    &format!("branch.{}", String::from_utf8_lossy(name)),
                    &["remote", "merge", "pushremote"],
                    ADMISSIBLE_BRANCH_KEYS,
                    &mut refusals,
                ) {
                    continue;
                }
                let fact = branch_fact_mut(&mut branch_tracking, name);
                set_unique_explicit_value(section, "remote", &mut fact.remote, |value| {
                    validate_safe_identifier(value, "branch remote")
                })?;
                append_explicit_values(section, "merge", &mut fact.merge_refs, |value| {
                    validate_safe_merge_ref(value)
                })?;
                set_unique_explicit_value(section, "pushremote", &mut fact.push_remote, |value| {
                    validate_safe_identifier(value, "branch pushRemote")
                })?;
            }
            "push" => {
                if section.header().subsection_name().is_some() {
                    return Err(unsafe_git_config("named push section"));
                }
                if collect_unknown_config_keys(
                    section,
                    "push",
                    &["default", "autosetupremote"],
                    &[],
                    &mut refusals,
                ) {
                    continue;
                }
                set_unique_explicit_value(section, "default", &mut push_default, |value| {
                    validate_push_default(value)
                })?;
                set_unique_explicit_value(
                    section,
                    "autosetupremote",
                    &mut push_auto_setup_remote,
                    validate_git_boolean,
                )?;
            }
            "core" => collect_transfer_core_keys(section, &mut refusals),
            // Split out of the arm below because it is the one section here a
            // user reaches without ever configuring transport: `git submodule
            // add` writes it for them.
            "submodule" => refusals.push(unsafe_submodule_reason(
                section
                    .header()
                    .subsection_name()
                    .and_then(|name| name.to_str().ok()),
            )),
            "lfs" => collect_lfs_keys(section, &mut refusals),
            "credential" | "http" | "https" | "url" | "protocol" | "transport" | "transfer"
            | "fetch" | "receive" | "uploadpack" | "ssh" => {
                // Eleven sections share this refusal, so naming the one that
                // matched is the difference between a reader knowing what to
                // look for and reading a category. The section name is one of
                // these literals and is always safe to print; the subsection
                // name is not, because for `url`, `http`, and `credential` it is
                // itself a URL that can carry `user:password@`.
                refusals.push(format!(
                    "unsupported transfer-affecting section [{section_name}]"
                ));
            }
            _ => {}
        }
    }

    if refusals.is_empty() {
        validate_remote_relationships(&remotes, &branch_tracking, remote_push_default.as_deref())?;
    }
    Ok(RemoteMappingScan {
        facts: GitRemoteMappingFacts {
            remotes,
            branch_tracking,
            remote_push_default,
            push_default,
            push_auto_setup_remote,
        },
        refusals,
    })
}

fn remote_fact_mut<'a>(
    remotes: &'a mut Vec<GitRemoteConfigFact>,
    name: &[u8],
) -> &'a mut GitRemoteConfigFact {
    if let Some(position) = remotes.iter().position(|remote| remote.name == name) {
        return &mut remotes[position];
    }
    remotes.push(GitRemoteConfigFact {
        name: name.to_vec(),
        fetch_urls: Vec::new(),
        push_urls: Vec::new(),
        fetch_refspecs: Vec::new(),
        push_refspecs: Vec::new(),
    });
    remotes.last_mut().expect("remote was just inserted")
}

fn branch_fact_mut<'a>(
    branches: &'a mut Vec<GitBranchTrackingFact>,
    name: &[u8],
) -> &'a mut GitBranchTrackingFact {
    if let Some(position) = branches.iter().position(|branch| branch.branch == name) {
        return &mut branches[position];
    }
    branches.push(GitBranchTrackingFact {
        branch: name.to_vec(),
        remote: None,
        merge_refs: Vec::new(),
        push_remote: None,
    });
    branches.last_mut().expect("branch was just inserted")
}

/// Keys inside `[branch "<name>"]` that Kin admits without modelling them.
///
/// This is not the allowlist inverted. A key in neither list still refuses, so
/// an unrecognised one fails closed exactly as before. These four are here
/// because they are what an ordinary editor-configured checkout carries, and
/// none of them changes which refs a fetch or push moves, what bytes those refs
/// carry, or which remote any branch maps to.
///
/// `rebase`, `description`, and `mergeoptions` shape a later local integration,
/// which is the same thing `[pull]` and `[merge]` do, and this scan already
/// admits both of those sections whole; refusing the per-branch spelling while
/// admitting the repository-wide one was an inconsistency rather than a
/// boundary. `vscode-merge-base` is an editor annotation Git itself never
/// reads: VS Code writes one per branch and recomputes it on demand, so an
/// eject that does not restore it loses nothing Git would have acted on.
const ADMISSIBLE_BRANCH_KEYS: &[&str] =
    &["rebase", "description", "mergeoptions", "vscode-merge-base"];

/// Collect every key outside the exact allowlist, naming each one.
///
/// `allowed` keys contribute facts Kin models and restores on eject.
/// `admissible` keys are ones this boundary has classified as unable to affect
/// transport, so they are dropped without a refusal and without a fact. A key
/// in neither list refuses, which is what keeps the subset fail-closed.
///
/// `scope` is the section spelling, which the caller builds from a subsection
/// name that has only been checked for control characters. That is not enough
/// to print: a `[remote "https://user:token@host/repo"]` section passes it and
/// would carry a credential into the refusal, so the subsection is dropped
/// unless it reads as a plain identifier. Key names are always safe, and the
/// values behind them are never printed. Without a name the reader is handed a
/// category and has to bisect their own config to find the line Kin meant.
///
/// Answers whether the section carried any, because a section that did is not
/// parsed for facts the caller would then have to discard.
fn collect_unknown_config_keys(
    section: &gix::config::file::Section<'_>,
    scope: &str,
    allowed: &[&str],
    admissible: &[&str],
    refusals: &mut Vec<String>,
) -> bool {
    let scope = printable_config_scope(scope);
    let before = refusals.len();
    for name in section.value_names() {
        let name = name.to_string();
        let recognized = allowed
            .iter()
            .chain(admissible.iter())
            .any(|known| name.eq_ignore_ascii_case(known));
        if !recognized {
            refusals.push(format!(
                "unsupported transfer-affecting repository-local key {scope}.{name}"
            ));
        }
    }
    refusals.len() != before
}

/// Classify one `[lfs]` section key by key rather than refusing it wholesale.
///
/// Git LFS moves bytes only through its `filter.lfs` clean and smudge commands,
/// and [`checkout_filter_facts`] refuses a configured `filter` at any scope, so
/// a repository actually using LFS is still refused there. An `[lfs]` section
/// is not that surface; it is client configuration, and two of its keys are
/// state git-lfs mints for itself. `lfs.repositoryformatversion` is the marker
/// `git lfs install --local` writes, and `[lfs "<endpoint>"] access` caches an
/// authentication mode git-lfs re-negotiates whenever it is absent. Dropping
/// either on eject changes nothing a user would find missing.
///
/// Everything else in the section still refuses, `lfs.url` most of all: it
/// names an endpoint Kin would have to restore and cannot.
fn collect_lfs_keys(section: &gix::config::file::Section<'_>, refusals: &mut Vec<String>) {
    let subsectioned = section.header().subsection_name().is_some();
    for name in section.value_names() {
        let name = name.to_string();
        let admissible = if subsectioned {
            name.eq_ignore_ascii_case("access")
        } else {
            name.eq_ignore_ascii_case("repositoryformatversion")
        };
        if !admissible {
            refusals.push(format!(
                "unsupported transfer-affecting repository-local key lfs.{name}"
            ));
        }
    }
}

/// Keep a section spelling printable, dropping a subsection that is not a plain
/// identifier rather than disclosing whatever it holds.
fn printable_config_scope(scope: &str) -> String {
    let Some((section, subsection)) = scope.split_once('.') else {
        return scope.to_string();
    };
    let printable = !subsection.is_empty()
        && subsection
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if printable {
        return scope.to_string();
    }
    section.to_string()
}

fn collect_transfer_core_keys(
    section: &gix::config::file::Section<'_>,
    refusals: &mut Vec<String>,
) {
    const TRANSFER_KEYS: &[&str] = &[
        "askpass",
        "gitproxy",
        "sshcommand",
        "httpproxy",
        "httpcookiefile",
    ];
    for name in section.value_names() {
        let name = name.to_string();
        if TRANSFER_KEYS
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
        {
            refusals.push(format!(
                "unsupported transfer-affecting core key core.{name}"
            ));
        }
    }
}

fn explicit_values(section: &gix::config::file::Section<'_>, key: &str) -> Result<Vec<Vec<u8>>> {
    let occurrence_count = section
        .value_names()
        .filter(|name| name.to_string().eq_ignore_ascii_case(key))
        .count();
    let values = section
        .values(key)
        .into_iter()
        .map(|value| value.to_vec())
        .collect::<Vec<_>>();
    if occurrence_count != values.len() {
        return Err(unsafe_git_config(
            "implicit repository-local transfer value",
        ));
    }
    Ok(values)
}

fn append_explicit_values(
    section: &gix::config::file::Section<'_>,
    key: &str,
    destination: &mut Vec<Vec<u8>>,
    validate: impl Fn(&[u8]) -> Result<()>,
) -> Result<()> {
    for value in explicit_values(section, key)? {
        validate(&value)?;
        destination.push(value);
    }
    Ok(())
}

fn set_unique_explicit_value(
    section: &gix::config::file::Section<'_>,
    key: &str,
    destination: &mut Option<Vec<u8>>,
    validate: impl Fn(&[u8]) -> Result<()>,
) -> Result<()> {
    for value in explicit_values(section, key)? {
        if destination.is_some() {
            return Err(unsafe_git_config(
                "duplicate scalar repository-local transfer value",
            ));
        }
        validate(&value)?;
        *destination = Some(value);
    }
    Ok(())
}

fn validate_safe_identifier(value: &[u8], label: &str) -> Result<()> {
    let utf8 = std::str::from_utf8(value)
        .map_err(|_| unsafe_git_config("non-UTF-8 repository-local transfer value"))?;
    if utf8.is_empty()
        || utf8.starts_with('-')
        || utf8
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(unsafe_git_config(format!("unsafe {label}")));
    }
    Ok(())
}

fn validate_safe_branch_name(value: &[u8]) -> Result<()> {
    validate_safe_identifier(value, "branch name")?;
    let mut full = b"refs/heads/".to_vec();
    full.extend_from_slice(value);
    gix::validate::reference::name(full.as_bstr())
        .map_err(|_| unsafe_git_config("invalid branch name"))?;
    Ok(())
}

fn validate_safe_remote_url(value: &[u8]) -> Result<()> {
    std::str::from_utf8(value).map_err(|_| unsafe_git_config("non-UTF-8 Git remote URL"))?;
    if value.is_empty()
        || value.starts_with(b"-")
        || value
            .iter()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'?' | b'#'))
    {
        return Err(unsafe_git_config("unsafe Git remote URL"));
    }
    let parsed = gix::Url::try_from(value.as_bstr())
        .map_err(|_| unsafe_git_config("unparseable Git remote URL"))?;
    if parsed.user.is_some() || parsed.password.is_some() {
        return Err(unsafe_git_config(
            "credential or userinfo in Git remote URL",
        ));
    }
    match parsed.scheme {
        gix::url::Scheme::File => {}
        gix::url::Scheme::Git
        | gix::url::Scheme::Ssh
        | gix::url::Scheme::Http
        | gix::url::Scheme::Https => {
            if parsed.host.as_deref().is_none_or(str::is_empty) {
                return Err(unsafe_git_config("network Git remote URL without a host"));
            }
        }
        gix::url::Scheme::Ext(_) => {
            return Err(unsafe_git_config("unsupported custom Git remote scheme"));
        }
    }
    if parsed.path_argument_safe().is_none() {
        return Err(unsafe_git_config("unsafe Git remote path"));
    }
    Ok(())
}

fn validate_safe_refspec(value: &[u8], operation: gix::refspec::parse::Operation) -> Result<()> {
    std::str::from_utf8(value).map_err(|_| unsafe_git_config("non-UTF-8 Git refspec"))?;
    if value
        .iter()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(unsafe_git_config("unsafe Git refspec"));
    }
    gix::refspec::parse(value.as_bstr(), operation)
        .map_err(|_| unsafe_git_config("invalid Git refspec"))?;
    Ok(())
}

fn validate_safe_merge_ref(value: &[u8]) -> Result<()> {
    std::str::from_utf8(value).map_err(|_| unsafe_git_config("non-UTF-8 branch merge ref"))?;
    gix::validate::reference::name(value.as_bstr())
        .map_err(|_| unsafe_git_config("invalid branch merge ref"))?;
    Ok(())
}

/// Accept exactly the spellings Git reads as a boolean.
///
/// An empty value is Git's own shorthand for true, so it is accepted with the
/// rest rather than treated as a missing value.
fn validate_git_boolean(value: &[u8]) -> Result<()> {
    let lowered = value.to_ascii_lowercase();
    if !matches!(
        lowered.as_slice(),
        b"" | b"true" | b"false" | b"yes" | b"no" | b"on" | b"off" | b"1" | b"0"
    ) {
        return Err(unsafe_git_config("non-boolean push.autoSetupRemote"));
    }
    Ok(())
}

fn validate_push_default(value: &[u8]) -> Result<()> {
    std::str::from_utf8(value).map_err(|_| unsafe_git_config("non-UTF-8 push.default"))?;
    if !matches!(
        value,
        b"nothing" | b"current" | b"upstream" | b"simple" | b"matching"
    ) {
        return Err(unsafe_git_config("unsupported push.default"));
    }
    Ok(())
}

fn validate_remote_relationships(
    remotes: &[GitRemoteConfigFact],
    branches: &[GitBranchTrackingFact],
    remote_push_default: Option<&[u8]>,
) -> Result<()> {
    let remote_names = remotes
        .iter()
        .map(|remote| remote.name.as_slice())
        .collect::<BTreeSet<_>>();
    let known_remote = |candidate: &[u8]| candidate == b"." || remote_names.contains(candidate);
    if remote_push_default.is_some_and(|name| !known_remote(name)) {
        return Err(unsafe_git_config(
            "remote.pushDefault names an unknown remote",
        ));
    }
    for branch in branches {
        if branch
            .remote
            .as_deref()
            .is_some_and(|name| !known_remote(name))
            || branch
                .push_remote
                .as_deref()
                .is_some_and(|name| !known_remote(name))
        {
            return Err(unsafe_git_config("branch tracking names an unknown remote"));
        }
        if !branch.merge_refs.is_empty() && branch.remote.is_none() {
            return Err(unsafe_git_config(
                "branch merge refs require an explicit remote",
            ));
        }
    }
    Ok(())
}

/// The refusal a repository carrying a submodule gets.
///
/// Kin does not model submodules yet, so refusing is correct. What the generic
/// transport wording could not do is get the reader from the failure to an
/// action: it named neither the submodule, nor the file the entry lives in, nor
/// whether anything could be done about it.
///
/// The subsection name is the submodule's path. Its URL lives in a key inside
/// the section and never in the header, so naming the path cannot disclose a
/// credential the way naming a `url` subsection would. A path that is not valid
/// UTF-8 has no spelling worth printing and is left out rather than turning a
/// refusal about submodules into one about encoding.
fn unsafe_submodule_reason(path: Option<&str>) -> String {
    let subject = match path {
        Some(path) => format!("unsupported submodule section for '{path}'"),
        None => "unsupported submodule section".to_string(),
    };
    format!(
        "{subject}; Kin cannot yet import a repository that carries submodules. Remove them with \
         'git submodule deinit --all' and drop the matching .gitmodules entries, or run kin init \
         inside the submodule's own repository"
    )
}

fn unsafe_git_config(reason: impl Into<String>) -> GitError {
    preflight_error(format!(
        "repository-local Git transport configuration is outside Kin's safe exact subset ({})",
        reason.into()
    ))
}

fn fingerprint_snapshot(snapshot: &LosslessGitRepository) -> Hash256 {
    let mut hash = FramedHash::new(b"kin.git.lossless.snapshot.v1");
    hash.bytes(snapshot.repository_id.as_str().as_bytes());
    hash.u64(object_format_code(snapshot.object_format));
    hash.u64(snapshot.objects.len() as u64);
    for object in &snapshot.objects {
        hash.u64(external_kind_code(object.object.kind));
        hash.bytes(object.object.oid.as_bytes());
        hash.bytes(object.body_hash.as_bytes());
        hash.u64(object.body_len);
    }
    encode_refs(&mut hash, &snapshot.refs);
    encode_head(&mut hash, &snapshot.head);
    hash.finish()
}

fn fingerprint_plan(plan: &SemanticGitImportPlan) -> Result<Hash256> {
    let mut hash = FramedHash::new(b"kin.git.semantic.import-plan.v1");
    hash.bytes(
        fingerprint_snapshot(&LosslessGitRepository {
            repository_id: plan.repository_id.clone(),
            object_format: plan.object_format,
            objects: plan.external_objects.clone(),
            refs: plan.refs.clone(),
            head: plan.head.clone(),
        })
        .as_bytes(),
    );
    hash.u64(plan.changes.len() as u64);
    for change in &plan.changes {
        hash.bytes(change.id.0.as_bytes());
    }
    hash.u64(plan.aliases.len() as u64);
    for alias in &plan.aliases {
        hash.bytes(alias.oid.as_bytes());
        hash.bytes(alias.change_id.0.as_bytes());
    }
    hash.u64(plan.commit_trees.len() as u64);
    for (oid, tree) in &plan.commit_trees {
        hash.bytes(oid.as_bytes());
        hash.bytes(compute_resolved_tree_hash(tree)?.as_bytes());
    }
    encode_head(&mut hash, &plan.workspace_seed.head);
    encode_optional_ref_target(&mut hash, plan.workspace_seed.base_target.as_ref());
    encode_optional_oid(&mut hash, plan.workspace_seed.base_commit_oid.as_ref());
    match plan.workspace_seed.base_tree_hash {
        Some(tree_hash) => {
            hash.u64(1);
            hash.bytes(tree_hash.as_bytes());
        }
        None => hash.u64(0),
    }
    Ok(hash.finish())
}

fn fingerprint_proof(proof: &GitMigrationPreflightProof) -> Hash256 {
    let mut hash = FramedHash::new(b"kin.git.migration-preflight-proof.v3");
    hash.bytes(proof.repository_id.as_str().as_bytes());
    hash.bytes(proof.snapshot_fingerprint.as_bytes());
    hash.bytes(proof.semantic_plan_fingerprint.as_bytes());
    hash.u64(u64::from(proof.index.present));
    hash.bytes(proof.index.raw_file_hash.as_bytes());
    hash.bytes(proof.index.logical_fingerprint.as_bytes());
    hash.bytes(proof.tracked_worktree.fingerprint.as_bytes());
    hash.bytes(proof.workspace_divergence.fingerprint.as_bytes());
    hash.bytes(proof.ignored_local.fingerprint.as_bytes());
    hash.u64(proof.remote_mapping.remotes.len() as u64);
    for remote in &proof.remote_mapping.remotes {
        hash.bytes(&remote.name);
        encode_byte_values(&mut hash, &remote.fetch_urls);
        encode_byte_values(&mut hash, &remote.push_urls);
        encode_byte_values(&mut hash, &remote.fetch_refspecs);
        encode_byte_values(&mut hash, &remote.push_refspecs);
    }
    hash.u64(proof.remote_mapping.branch_tracking.len() as u64);
    for branch in &proof.remote_mapping.branch_tracking {
        hash.bytes(&branch.branch);
        encode_optional_bytes(&mut hash, branch.remote.as_deref());
        hash.u64(branch.merge_refs.len() as u64);
        for merge_ref in &branch.merge_refs {
            hash.bytes(merge_ref);
        }
        encode_optional_bytes(&mut hash, branch.push_remote.as_deref());
    }
    encode_optional_bytes(
        &mut hash,
        proof.remote_mapping.remote_push_default.as_deref(),
    );
    encode_optional_bytes(&mut hash, proof.remote_mapping.push_default.as_deref());
    encode_optional_bytes(
        &mut hash,
        proof.remote_mapping.push_auto_setup_remote.as_deref(),
    );
    hash.finish()
}

fn encode_byte_values(hash: &mut FramedHash, values: &[Vec<u8>]) {
    hash.u64(values.len() as u64);
    for value in values {
        hash.bytes(value);
    }
}

pub(crate) fn open_repo_with_user_ignore_config(path: &Path) -> Result<gix::Repository> {
    let dot_git = path.join(".git");
    let open_path = if dot_git.is_dir() { &dot_git } else { path };
    let options = gix::open::Options::default()
        .strict_config(true)
        .config_overrides(["core.useReplaceRefs=true"]);
    gix::open_opts(open_path, options).map_err(|error| {
        preflight_error(format!(
            "open Git repository with resolved user ignore configuration: {error}"
        ))
    })
}

pub(crate) fn local_ignore_inputs(repo: &gix::Repository) -> Result<Vec<GitLocalIgnoreInputFact>> {
    let mut inputs = Vec::new();
    if let Some(path) = resolved_global_excludes_path(repo)? {
        if let Some(body) = read_optional_regular_file(&path)? {
            inputs.push(local_ignore_input(
                GitLocalIgnoreSourceKind::ResolvedGlobalExcludes,
                inputs.len(),
                body,
            )?);
        }
    }
    let info_exclude = repo.common_dir().join("info/exclude");
    if let Some(body) = read_optional_regular_file(&info_exclude)? {
        inputs.push(local_ignore_input(
            GitLocalIgnoreSourceKind::RepositoryInfoExclude,
            inputs.len(),
            body,
        )?);
    }
    Ok(inputs)
}

pub(crate) fn frozen_ignore_stack<'repo>(
    repo: &'repo gix::Repository,
    index: &gix::index::File,
    inputs: &[GitLocalIgnoreInputFact],
) -> Result<(gix::AttributeStack<'repo>, bool)> {
    let ignore_case = repo
        .filesystem_options()
        .map_err(|error| preflight_error(format!("resolve Git filesystem options: {error}")))?
        .ignore_case;
    let case = if ignore_case {
        gix::glob::pattern::Case::Fold
    } else {
        gix::glob::pattern::Case::Sensitive
    };
    let parse = gix::worktree::stack::state::ignore::ParseIgnore {
        support_precious: false,
    };
    let mut globals = gix::ignore::Search::default();
    for input in inputs {
        let source = match input.source_kind {
            GitLocalIgnoreSourceKind::ResolvedGlobalExcludes => {
                PathBuf::from(".kin/frozen-global-excludes")
            }
            GitLocalIgnoreSourceKind::RepositoryInfoExclude => {
                PathBuf::from(".kin/frozen-info-exclude")
            }
        };
        globals.add_patterns_buffer(&input.body, source, None, parse);
    }
    let ignore = gix::worktree::stack::state::Ignore::new(
        gix::ignore::Search::default(),
        globals,
        None,
        // Shared `.gitignore` policy comes from the exact committed index/ODB,
        // never an ambient filesystem fallback.
        gix::worktree::stack::state::ignore::Source::IdMapping,
        parse,
    );
    let state = gix::worktree::stack::State::IgnoreStack(ignore);
    let mut id_mappings = state.id_mappings_from_index(index, index.path_backing(), case);
    for entry in index
        .entries()
        .iter()
        .filter(|entry| entry.mode == gix::index::entry::Mode::FILE_EXECUTABLE)
    {
        let path = entry.path(index);
        let basename = path
            .rfind_byte(b'/')
            .map_or(path, |position| path[position + 1..].as_bstr());
        let is_ignore = match case {
            gix::glob::pattern::Case::Sensitive => basename == b".gitignore",
            gix::glob::pattern::Case::Fold => basename.eq_ignore_ascii_case(b".gitignore"),
        };
        if is_ignore {
            id_mappings.push((path.to_owned(), entry.id));
        }
    }
    id_mappings.sort_by(|left, right| left.0.cmp(&right.0));
    let stack = gix::worktree::Stack::new(
        repo.workdir()
            .ok_or_else(|| preflight_error("ignore matcher requires a Git worktree"))?,
        state,
        case,
        Vec::with_capacity(512),
        id_mappings,
    );
    Ok((gix::AttributeStack::new(stack, repo), ignore_case))
}

fn resolved_global_excludes_path(repo: &gix::Repository) -> Result<Option<PathBuf>> {
    if let Some(configured) = repo.config_snapshot().trusted_path("core.excludesFile") {
        let configured = configured.map_err(|error| {
            preflight_error(format!(
                "resolve configured global Git excludes file: {error}"
            ))
        })?;
        if !configured.as_os_str().is_empty() {
            return Ok(Some(configured.into_owned()));
        }
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(Some(PathBuf::from(xdg).join("git/ignore")));
    }
    Ok(std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/git/ignore")))
}

fn read_optional_regular_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(GitError::io(path, error)),
    };
    if !metadata.is_file() {
        return Err(preflight_error(
            "resolved Git ignore input is not a regular file",
        ));
    }
    fs::read(path)
        .map(Some)
        .map_err(|error| GitError::io(path, error))
}

fn local_ignore_input(
    source_kind: GitLocalIgnoreSourceKind,
    order: usize,
    body: Vec<u8>,
) -> Result<GitLocalIgnoreInputFact> {
    let body_len = u64::try_from(body.len())
        .map_err(|_| preflight_error("local Git ignore input exceeds u64 length"))?;
    Ok(GitLocalIgnoreInputFact {
        source_kind,
        order,
        body_hash: digest(&body),
        body_len,
        body,
    })
}

fn encode_refs(hash: &mut FramedHash, refs: &RepositoryRefState) {
    hash.u64(refs.refs.len() as u64);
    for repository_ref in &refs.refs {
        hash.bytes(repository_ref.name.as_bytes());
        encode_ref_target(hash, &repository_ref.target);
    }
    encode_optional_bytes(hash, refs.default_ref.as_ref().map(|name| name.as_bytes()));
}

fn encode_head(hash: &mut FramedHash, head: &WorkspaceHead) {
    match head {
        WorkspaceHead::Symbolic { target } => {
            hash.u64(1);
            hash.bytes(target.as_bytes());
        }
        WorkspaceHead::Detached { target } => {
            hash.u64(2);
            encode_ref_target(hash, target);
        }
    }
}

fn encode_optional_ref_target(hash: &mut FramedHash, target: Option<&RefTarget>) {
    match target {
        Some(target) => {
            hash.u64(1);
            encode_ref_target(hash, target);
        }
        None => hash.u64(0),
    }
}

fn encode_ref_target(hash: &mut FramedHash, target: &RefTarget) {
    match target {
        RefTarget::Change { change_id } => {
            hash.u64(1);
            hash.bytes(change_id.0.as_bytes());
        }
        RefTarget::ExternalObject { object } => {
            hash.u64(2);
            hash.u64(external_kind_code(object.kind));
            hash.bytes(object.oid.as_bytes());
        }
        RefTarget::Symbolic { target } => {
            hash.u64(3);
            hash.bytes(target.as_bytes());
        }
    }
}

fn encode_optional_oid(hash: &mut FramedHash, oid: Option<&GitObjectId>) {
    match oid {
        Some(oid) => {
            hash.u64(1);
            hash.bytes(oid.as_bytes());
        }
        None => hash.u64(0),
    }
}

fn encode_optional_bytes(hash: &mut FramedHash, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            hash.u64(1);
            hash.bytes(bytes);
        }
        None => hash.u64(0),
    }
}

struct FramedHash {
    bytes: Vec<u8>,
}

impl FramedHash {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Self { bytes: Vec::new() };
        hash.bytes(domain);
        hash
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn finish(self) -> Hash256 {
        digest(&self.bytes)
    }
}

fn git_object_id(oid: gix::ObjectId) -> Result<GitObjectId> {
    match oid.as_bytes() {
        bytes if bytes.len() == 20 => {
            let mut value = [0_u8; 20];
            value.copy_from_slice(bytes);
            Ok(GitObjectId::sha1(value))
        }
        bytes if bytes.len() == 32 => {
            let mut value = [0_u8; 32];
            value.copy_from_slice(bytes);
            Ok(GitObjectId::sha256(value))
        }
        bytes => Err(preflight_error(format!(
            "unsupported Git object ID width {}",
            bytes.len()
        ))),
    }
}

fn object_format_code(format: GitObjectFormat) -> u64 {
    match format {
        GitObjectFormat::Sha1 => 1,
        GitObjectFormat::Sha256 => 2,
    }
}

fn external_kind_code(kind: ExternalObjectKind) -> u64 {
    match kind {
        ExternalObjectKind::Commit => 1,
        ExternalObjectKind::Tree => 2,
        ExternalObjectKind::Blob => 3,
        ExternalObjectKind::Tag => 4,
    }
}

fn ignored_kind_code(kind: IgnoredLocalEntryKind) -> u64 {
    match kind {
        IgnoredLocalEntryKind::File => 1,
        IgnoredLocalEntryKind::Symlink => 2,
        IgnoredLocalEntryKind::Directory => 3,
        IgnoredLocalEntryKind::Other => 4,
    }
}

fn local_ignore_source_code(kind: GitLocalIgnoreSourceKind) -> u64 {
    match kind {
        GitLocalIgnoreSourceKind::ResolvedGlobalExcludes => 1,
        GitLocalIgnoreSourceKind::RepositoryInfoExclude => 2,
    }
}

fn ignored_entry_kind(metadata: &fs::Metadata) -> IgnoredLocalEntryKind {
    if metadata.file_type().is_symlink() {
        IgnoredLocalEntryKind::Symlink
    } else if metadata.is_file() {
        IgnoredLocalEntryKind::File
    } else if metadata.is_dir() {
        IgnoredLocalEntryKind::Directory
    } else {
        IgnoredLocalEntryKind::Other
    }
}

pub(crate) fn hook_kind(metadata: &fs::Metadata) -> LocalGitHookKind {
    if metadata.file_type().is_symlink() {
        LocalGitHookKind::Symlink
    } else if metadata.is_file() {
        LocalGitHookKind::File
    } else if metadata.is_dir() {
        LocalGitHookKind::Directory
    } else {
        LocalGitHookKind::Other
    }
}

pub(crate) fn stable_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn preflight_error(reason: impl Into<String>) -> GitError {
    GitError::MigrationPreflight(reason.into())
}

/// Exact names for one directory listing, ordered by those exact bytes.
///
/// Resolving into a `Result` collection would stop at the first name this host
/// cannot represent, so a worktree holding three of them would report one and
/// the operator would discover the next only by re-running. Admission refuses
/// with every non-representable entry named instead, which is what makes one
/// refusal enough to act on.
pub(crate) fn exact_directory_names(
    directory: &Path,
    entries: Vec<fs::DirEntry>,
) -> Result<Vec<(Vec<u8>, fs::DirEntry)>> {
    exact_directory_names_resolved_by(directory, entries, os_bytes)
}

/// The body above, with the name resolver supplied.
///
/// On Unix `os_bytes` cannot fail, so the gathering behaviour would otherwise
/// have no execution anywhere except Windows. Taking the resolver as an
/// argument lets both platforms run the same code against a chosen set of
/// unrepresentable names.
fn exact_directory_names_resolved_by(
    directory: &Path,
    entries: Vec<fs::DirEntry>,
    mut resolve: impl FnMut(&std::ffi::OsStr) -> Result<Vec<u8>>,
) -> Result<Vec<(Vec<u8>, fs::DirEntry)>> {
    let mut named = Vec::with_capacity(entries.len());
    let mut unrepresentable = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        match resolve(&name) {
            Ok(bytes) => named.push((bytes, entry)),
            // Debug rendering of an OS string escapes ill-formed units rather
            // than repairing them, so two distinct names this host cannot
            // represent do not print alike in the refusal that names both.
            Err(_) => unrepresentable.push(format!("{name:?}")),
        }
    }
    if !unrepresentable.is_empty() {
        unrepresentable.sort();
        let (subject, verb, object) = if unrepresentable.len() == 1 {
            ("entry", "is", "it")
        } else {
            ("entries", "are", "them")
        };
        return Err(preflight_error(format!(
            "{} {subject} under {} {verb} not well-formed Unicode, so this platform cannot name \
             {object} exactly: {}",
            unrepresentable.len(),
            directory.display(),
            unrepresentable.join(", ")
        )));
    }
    named.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(named)
}

/// Exact bytes of one filesystem entry name.
///
/// Unix names are already byte strings, so they are exact as read.
#[cfg(unix)]
fn os_bytes(value: &std::ffi::OsStr) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(value.as_bytes().to_vec())
}

/// Exact bytes of one filesystem entry name.
///
/// Windows names are UTF-16 and carry no byte encoding of their own, so the
/// exact byte form of a well-formed name is its UTF-8 encoding, which is the
/// encoding Git itself records. A name the filesystem holds as ill-formed
/// UTF-16 has no exact byte form here and fails rather than being repaired
/// with replacement characters: a lossy name would let two distinct entries
/// collapse to the same bytes in the tracked fingerprint and in the sort that
/// fingerprint depends on, which is a silent proof forgery rather than a
/// missing feature.
#[cfg(not(unix))]
fn os_bytes(value: &std::ffi::OsStr) -> Result<Vec<u8>> {
    value
        .to_str()
        .map(|name| name.as_bytes().to_vec())
        .ok_or_else(|| {
            preflight_error(format!(
                "worktree entry {} is not well-formed Unicode, so this platform cannot name it \
                 exactly",
                value.to_string_lossy()
            ))
        })
}

/// Exact bytes of one symbolic-link target read back from the worktree.
#[cfg(unix)]
fn path_bytes(value: &Path) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(value.as_os_str().as_bytes().to_vec())
}

/// Exact bytes of one symbolic-link target read back from the worktree.
///
/// Git stores link targets as UTF-8 with `/` separators. Windows returns a
/// reparse point's substitute name as UTF-16, and may render the separators
/// Git wrote as `\`. A backslash cannot occur literally inside a Windows path
/// component, so one read back from the filesystem is unambiguously a
/// separator and is restored to the form Git committed; a target that already
/// uses `/` is unchanged by the same rewrite. A target the filesystem holds as
/// ill-formed UTF-16 has no exact byte form and fails.
#[cfg(not(unix))]
fn path_bytes(value: &Path) -> Result<Vec<u8>> {
    value
        .to_str()
        .map(|target| target.replace('\\', "/").into_bytes())
        .ok_or_else(|| {
            preflight_error(format!(
                "symbolic-link target {} is not well-formed Unicode, so this platform cannot \
                 prove it exactly",
                value.display()
            ))
        })
}

/// Whether the host filesystem records an executable bit at all.
#[cfg(unix)]
const fn filesystem_records_executable_bit() -> bool {
    true
}

/// Whether the host filesystem records an executable bit at all.
///
/// Windows filesystems do not. Git for Windows detects this at repository
/// creation and records `core.fileMode=false`, after which the index carries
/// the exact mode and the worktree is never consulted for it.
#[cfg(not(unix))]
const fn filesystem_records_executable_bit() -> bool {
    false
}

#[cfg(unix)]
fn filesystem_executable(metadata: &fs::Metadata) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    Ok(metadata.permissions().mode() & 0o100 != 0)
}

/// Fail-closed backstop for a host with no executable bit to read.
///
/// `worktree_materialization` never selects [`ExecutableModeAuthority::
/// WorktreeMode`] on such a host, so this is unreachable by construction; it
/// refuses rather than inventing a bit if that ever stops being true.
#[cfg(not(unix))]
fn filesystem_executable(_metadata: &fs::Metadata) -> Result<bool> {
    Err(preflight_error(
        "byte-exact executable-mode proof was requested from a filesystem that records no \
         executable bit",
    ))
}

/// Executable-bit observation for one local hook file.
pub(crate) fn hook_executability(metadata: &fs::Metadata) -> Result<LocalGitHookExecutability> {
    if !filesystem_records_executable_bit() {
        return Ok(LocalGitHookExecutability::Unrecorded);
    }
    Ok(if filesystem_executable(metadata)? {
        LocalGitHookExecutability::Executable
    } else {
        LocalGitHookExecutability::NotExecutable
    })
}

/// Platform materialization contracts, exercised on every target.
///
/// The suite below builds real repositories carrying symlinks, executable
/// bits, and non-UTF-8 paths, so it is unix-only. These cases instead pin the
/// decisions that differ per platform, and each asserts both arms, so the
/// Windows leg proves the Windows behavior rather than compiling it.
#[cfg(test)]
mod platform_materialization_tests {
    use std::ffi::OsString;

    use super::*;
    use crate::test_support::fixture_git;

    fn git(repository: &std::path::Path, arguments: &[&str]) {
        let output = fixture_git()
            .current_dir(repository)
            .args(arguments)
            .output()
            .expect("run fixture git");
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn empty_repository(root: &std::path::Path) -> gix::Repository {
        std::fs::create_dir_all(root).expect("repository directory");
        git(root, &["init", "--initial-branch=main"]);
        open_repo(root).expect("open fixture repository")
    }

    #[test]
    fn entry_name_bytes_are_exact_for_a_representable_name() {
        let name = OsString::from("ordinary-name.dat");
        assert_eq!(os_bytes(&name).expect("exact name"), b"ordinary-name.dat");
    }

    #[test]
    fn an_entry_name_this_host_cannot_represent_exactly_fails_rather_than_being_repaired() {
        #[cfg(unix)]
        {
            // Unix names are bytes, so every name has an exact form.
            use std::os::unix::ffi::OsStringExt as _;

            let name = OsString::from_vec(b"raw-\xff-name.dat".to_vec());
            assert_eq!(os_bytes(&name).expect("exact name"), b"raw-\xff-name.dat");
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt as _;

            // A lone high surrogate is ill-formed UTF-16 and has no UTF-8
            // encoding. Repairing it would let two distinct entries hash to
            // the same bytes in the tracked fingerprint.
            let name = OsString::from_wide(&[0x0072, 0xD800, 0x0074]);
            let error = os_bytes(&name).expect_err("ill-formed name is refused");
            assert!(
                error.to_string().contains("not well-formed Unicode"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn symlink_target_bytes_use_the_encoding_git_committed() {
        #[cfg(unix)]
        {
            // A backslash is an ordinary Unix filename byte and is preserved.
            let target = std::path::PathBuf::from("dir\\odd/name");
            assert_eq!(path_bytes(&target).expect("exact target"), b"dir\\odd/name");
        }
        #[cfg(windows)]
        {
            // Windows may return the separators Git wrote as backslashes; a
            // backslash cannot occur literally inside a path component there,
            // so restoring them is exact, and a target that already uses `/`
            // is unchanged.
            assert_eq!(
                path_bytes(&std::path::PathBuf::from("dir\\name")).expect("exact target"),
                b"dir/name"
            );
            assert_eq!(
                path_bytes(&std::path::PathBuf::from("dir/name")).expect("exact target"),
                b"dir/name"
            );
        }
    }

    #[test]
    fn a_default_repository_reads_modes_and_links_from_its_platform() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repository = empty_repository(&temp.path().join("source"));
        let (executable, symlinks) =
            worktree_materialization(&repository).expect("default materialization");

        if filesystem_records_executable_bit() {
            assert_eq!(executable, ExecutableModeAuthority::WorktreeMode);
            assert_eq!(symlinks, SymlinkMaterialization::Link);
            return;
        }

        assert_eq!(executable, ExecutableModeAuthority::IndexMode);
        // Whether Git recorded core.symlinks at creation depends on the
        // privilege this host granted it, so pin the resolution against what
        // the repository actually says rather than against one host's default.
        let recorded = repository.config_snapshot().boolean("core.symlinks");
        let expected = match recorded {
            Some(true) => SymlinkMaterialization::Link,
            Some(false) => {
                SymlinkMaterialization::TargetTextFile(SymlinkCapabilitySource::RepositoryRecorded)
            }
            None => {
                SymlinkMaterialization::TargetTextFile(SymlinkCapabilitySource::PlatformDefault)
            }
        };
        assert_eq!(
            symlinks, expected,
            "core.symlinks resolved to {recorded:?}, which must decide both the materialization \
             and who decided it"
        );
    }

    #[test]
    fn core_symlinks_selects_the_materialization_only_where_the_filesystem_needs_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let repository = empty_repository(&root);
        git(&root, &["config", "core.symlinks", "true"]);
        let repository = open_repo(repository.workdir().expect("workdir")).expect("reopen");

        let (_, symlinks) = worktree_materialization(&repository).expect("materialization");
        assert_eq!(
            symlinks,
            SymlinkMaterialization::Link,
            "core.symlinks=true means a real link on every platform"
        );
    }

    #[test]
    fn core_file_mode_true_is_refused_only_where_no_executable_bit_exists() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let repository = empty_repository(&root);
        git(&root, &["config", "core.fileMode", "true"]);
        let repository = open_repo(repository.workdir().expect("workdir")).expect("reopen");

        let resolved = worktree_materialization(&repository);
        if filesystem_records_executable_bit() {
            let (executable, _) = resolved.expect("a filesystem mode is readable here");
            assert_eq!(
                executable,
                ExecutableModeAuthority::WorktreeMode,
                "the worktree stays the mode authority where the bit exists"
            );
        } else {
            let error = resolved.expect_err("a synthesized mode is not a proof");
            assert!(
                error.to_string().contains("core.fileMode=true"),
                "the refusal must name the setting that caused it: {error}"
            );
        }
    }

    /// Drive `prove_tracked_entry` directly with a chosen materialization.
    ///
    /// `worktree_materialization` never returns the Windows shapes on Unix, so
    /// the cases below would otherwise only be compiled here and never run. The
    /// walk state is small enough to build outright, which lets both platforms
    /// execute the same comparison logic against a real store and real files.
    ///
    /// Answers with what the entry was recorded as differing by, so a case
    /// asserting agreement asserts an empty list rather than the absence of an
    /// error a matching entry could never have produced.
    fn prove_one_entry(
        absolute: &std::path::Path,
        entry: TreeEntry,
        blob_store: &BlobStore,
        executable_authority: ExecutableModeAuthority,
        symlink_materialization: SymlinkMaterialization,
    ) -> Result<Vec<GitWorkspaceDivergence>> {
        let path = RepoPath::from_bytes(b"tracked".to_vec()).expect("repo path");
        let expected = ExpectedIndexEntry {
            mode: match entry {
                TreeEntry::Blob {
                    executable: true, ..
                } => gix::index::entry::Mode::FILE_EXECUTABLE,
                TreeEntry::Blob { .. } => gix::index::entry::Mode::FILE,
                TreeEntry::Symlink { .. } => gix::index::entry::Mode::SYMLINK,
                TreeEntry::Gitlink { .. } => gix::index::entry::Mode::COMMIT,
            },
            oid: GitObjectId::sha1([0; 20]),
            tree_entry: entry,
        };
        let mut expected_entries = BTreeMap::new();
        expected_entries.insert(path.clone(), expected);
        let indexed = BTreeSet::new();
        let mut divergence = DivergenceLog::default();
        let mut state = WorktreeWalk {
            expected: &expected_entries,
            indexed: &indexed,
            blob_store,
            seen: BTreeSet::new(),
            tracked_hash: FramedHash::new(b"kin.git.preflight.worktree.test"),
            gitlink_count: 0,
            host_unrepresentable_count: 0,
            ignored: Vec::new(),
            executable_authority,
            symlink_materialization,
            diagnosis: None,
            divergence: &mut divergence,
        };
        let metadata = fs::symlink_metadata(absolute).expect("entry metadata");
        prove_tracked_entry(absolute, &path, &metadata, expected, &mut state)?;
        Ok(divergence.entries)
    }

    /// The one sentence a single recorded divergence carries.
    fn only_detail(entries: &[GitWorkspaceDivergence]) -> String {
        let [entry] = entries else {
            panic!("expected exactly one divergence, got {entries:?}");
        };
        entry.detail.clone()
    }

    #[test]
    fn a_link_target_written_as_a_regular_file_proves_against_the_committed_target() {
        let temp = tempfile::tempdir().expect("tempdir");
        let blob_store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let target_blob = blob_store.write(b"src/main.rs").expect("target blob");

        let tracked = temp.path().join("tracked");
        fs::write(&tracked, b"src/main.rs").expect("target text file");
        let matched = prove_one_entry(
            &tracked,
            TreeEntry::Symlink { target_blob },
            &blob_store,
            ExecutableModeAuthority::IndexMode,
            SymlinkMaterialization::TargetTextFile(SymlinkCapabilitySource::RepositoryRecorded),
        )
        .expect("the target text file is observed");
        assert!(
            matched.is_empty(),
            "the target text file matches the committed target: {matched:?}"
        );

        fs::write(&tracked, b"src/other.rs").expect("rewrite target text file");
        let diverged = prove_one_entry(
            &tracked,
            TreeEntry::Symlink { target_blob },
            &blob_store,
            ExecutableModeAuthority::IndexMode,
            SymlinkMaterialization::TargetTextFile(SymlinkCapabilitySource::RepositoryRecorded),
        )
        .expect("a different target is observed rather than refused");
        let detail = only_detail(&diverged);
        assert!(
            detail.contains("target differs from the committed"),
            "unexpected detail: {detail}"
        );
    }

    /// Create a real symbolic link, or say why this host could not.
    ///
    /// A test that returns early when the privilege is missing reports `ok`
    /// for both "the refusal was proven" and "nothing ran", and the log cannot
    /// tell them apart. The privilege is therefore asserted rather than
    /// assumed: a host that genuinely cannot create links records that
    /// deliberately by setting `KIN_GIT_TEST_NO_SYMLINK_PRIVILEGE`, and prints a
    /// skip marker instead of a silent pass. CI sets nothing, so a runner
    /// without the privilege turns the leg red rather than green.
    #[cfg(windows)]
    fn create_real_symlink_or_skip(target: &str, link: &std::path::Path) -> bool {
        let Err(error) = std::os::windows::fs::symlink_file(target, link) else {
            return true;
        };
        assert!(
            std::env::var_os("KIN_GIT_TEST_NO_SYMLINK_PRIVILEGE").is_some(),
            "this host cannot create a symbolic link ({error}), so the refusal that keeps Kin \
             from reading through one was never exercised. Enable Developer Mode or grant \
             SeCreateSymbolicLinkPrivilege, or set KIN_GIT_TEST_NO_SYMLINK_PRIVILEGE=1 to record \
             deliberately that this run proves nothing about it"
        );
        println!(
            "SKIPPED: no symbolic-link privilege on this host, so the real-link refusal was not \
             exercised"
        );
        false
    }

    #[cfg(unix)]
    fn create_real_symlink_or_skip(target: &str, link: &std::path::Path) -> bool {
        std::os::unix::fs::symlink(target, link).expect("symlink");
        true
    }

    #[test]
    fn a_real_link_where_links_are_off_is_reported_rather_than_read_through() {
        let temp = tempfile::tempdir().expect("tempdir");
        let blob_store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let target_blob = blob_store.write(b"src/main.rs").expect("target blob");

        // Both sources resolve to the same materialization and must produce
        // the same report, but they must not blame the same party for it.
        for (source, blamed) in [
            (
                SymlinkCapabilitySource::RepositoryRecorded,
                "records core.symlinks=false",
            ),
            (
                SymlinkCapabilitySource::PlatformDefault,
                "records no core.symlinks value",
            ),
        ] {
            let tracked = temp.path().join(format!("tracked-{source:?}"));
            if !create_real_symlink_or_skip("src/main.rs", &tracked) {
                return;
            }

            let diverged = prove_one_entry(
                &tracked,
                TreeEntry::Symlink { target_blob },
                &blob_store,
                ExecutableModeAuthority::IndexMode,
                SymlinkMaterialization::TargetTextFile(source),
            )
            .expect("a real link contradicts a worktree that cannot hold one");
            let rendered = only_detail(&diverged);
            assert!(
                rendered.contains("is a real symbolic link"),
                "unexpected detail: {rendered}"
            );
            assert!(
                rendered.contains(blamed),
                "the report must name who decided the materialization: {rendered}"
            );
        }
    }

    #[test]
    fn an_index_mode_authority_does_not_reread_the_worktree_for_the_executable_bit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let blob_store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let hash = blob_store.write(b"#!/bin/sh\nexit 0\n").expect("blob");

        let tracked = temp.path().join("tracked");
        fs::write(&tracked, b"#!/bin/sh\nexit 0\n").expect("tracked file");

        // The file carries no executable bit anywhere, yet the committed tree
        // says it is executable. Under index authority the index proof already
        // settled that, so the entry agrees; under worktree authority the same
        // file must be reported as differing.
        let matched = prove_one_entry(
            &tracked,
            TreeEntry::Blob {
                hash,
                executable: true,
            },
            &blob_store,
            ExecutableModeAuthority::IndexMode,
            SymlinkMaterialization::TargetTextFile(SymlinkCapabilitySource::RepositoryRecorded),
        )
        .expect("the index carries the exact mode");
        assert!(
            matched.is_empty(),
            "index authority settles the mode without rereading the worktree: {matched:?}"
        );

        let compared = prove_one_entry(
            &tracked,
            TreeEntry::Blob {
                hash,
                executable: true,
            },
            &blob_store,
            ExecutableModeAuthority::WorktreeMode,
            SymlinkMaterialization::Link,
        );
        // Which outcome is correct is decided by the same predicate the
        // production path decides on, so both hosts assert the behavior they
        // actually have rather than one of them asserting the other's.
        if filesystem_records_executable_bit() {
            let rendered = only_detail(&compared.expect("a mode difference is observed"));
            assert!(
                rendered.contains("executable mode differs"),
                "unexpected detail: {rendered}"
            );
        } else {
            // A host with no executable bit never reaches worktree authority
            // through `worktree_materialization`. Driving it here is what keeps
            // the fail-closed backstop from rotting into a silent `false`.
            let error = compared.expect_err("a mode this host cannot read is refused");
            assert!(
                error.to_string().contains("records no executable bit"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn every_entry_this_host_cannot_name_is_reported_in_one_refusal() {
        let temp = tempfile::tempdir().expect("tempdir");
        for name in ["first", "keeps", "second"] {
            fs::write(temp.path().join(name), b"x").expect("entry");
        }
        let entries = fs::read_dir(temp.path())
            .expect("read_dir")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("entries");

        // `os_bytes` cannot fail on Unix, so the resolver is supplied here to
        // give both platforms the same set of unrepresentable names to gather.
        let error = exact_directory_names_resolved_by(temp.path(), entries, |name| {
            if name == std::ffi::OsStr::new("keeps") {
                Ok(b"keeps".to_vec())
            } else {
                Err(preflight_error("not well-formed Unicode"))
            }
        })
        .expect_err("a host that cannot name an entry cannot walk the directory");

        let rendered = error.to_string();
        assert!(
            rendered.contains("\"first\"") && rendered.contains("\"second\""),
            "the refusal must name every entry it could not represent, not the first: {rendered}"
        );
        assert!(
            rendered.contains("2 entries"),
            "the refusal must count what it found: {rendered}"
        );
        assert!(
            !rendered.contains("\"keeps\""),
            "a representable entry is not a failure: {rendered}"
        );
    }

    #[test]
    fn a_directory_this_host_can_name_entirely_is_ordered_by_exact_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        for name in ["b", "a", "c"] {
            fs::write(temp.path().join(name), b"x").expect("entry");
        }
        let entries = fs::read_dir(temp.path())
            .expect("read_dir")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("entries");

        let named = exact_directory_names(temp.path(), entries).expect("all names representable");
        let order: Vec<Vec<u8>> = named.into_iter().map(|(name, _)| name).collect();
        assert_eq!(
            order,
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "gathering the failures must not disturb the byte ordering the fingerprint depends on"
        );
    }

    #[test]
    fn hook_executability_reports_what_the_filesystem_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let hook = temp.path().join("pre-commit");
        std::fs::write(&hook, b"#!/bin/sh\nexit 0\n").expect("hook");
        let metadata = std::fs::symlink_metadata(&hook).expect("hook metadata");

        let observed = hook_executability(&metadata).expect("hook executability");
        if filesystem_records_executable_bit() {
            assert_eq!(observed, LocalGitHookExecutability::NotExecutable);
        } else {
            assert_eq!(
                observed,
                LocalGitHookExecutability::Unrecorded,
                "a platform with no executable bit must not report a hook as non-executable"
            );
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsString;
    use std::io::Write as _;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Output;

    use tempfile::TempDir;

    use super::*;
    use crate::test_support::{fixture_git, FixtureGitCommand};
    use crate::{plan_semantic_git_import, GitError};

    struct Fixture {
        temp: TempDir,
        repo: PathBuf,
        store: BlobStore,
        snapshot: LosslessGitRepository,
        plan: SemanticGitImportPlan,
    }

    impl Fixture {
        fn clean() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path().join("source");
            fs::create_dir(&repo).expect("source directory");
            git(&repo, &["init", "--initial-branch=main"]);
            configure_identity(&repo);
            git(&repo, &["config", "core.filemode", "true"]);

            fs::create_dir_all(repo.join("src")).expect("src");
            fs::write(repo.join("src/main.rs"), b"fn main() {}\n").expect("main.rs");
            fs::write(
                repo.join("compose.yaml"),
                b"services:\n  app:\n    image: example/app:latest\n",
            )
            .expect("compose");
            fs::write(repo.join("payload.bin"), [0, 0xff, 0x80, 1]).expect("binary");
            fs::write(repo.join("script.sh"), b"#!/bin/sh\nexit 0\n").expect("script");
            let mut permissions = fs::metadata(repo.join("script.sh"))
                .expect("script metadata")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(repo.join("script.sh"), permissions).expect("chmod script");
            symlink(Path::new("src/main.rs"), repo.join("source-link")).expect("symlink");
            // Darwin rejects ill-formed UTF-8 at the filesystem syscall
            // boundary. Other Unix targets exercise a truly non-UTF-8 name;
            // Darwin still exercises decomposed raw-byte identity.
            #[cfg(target_vendor = "apple")]
            let raw_name = OsString::from_vec(b"raw-\xf0\x9f\xa7\xac-name.dat".to_vec());
            #[cfg(not(target_vendor = "apple"))]
            let raw_name = OsString::from_vec(b"raw-\xff-name.dat".to_vec());
            fs::write(repo.join(raw_name), b"raw path\n").expect("raw path");
            fs::write(repo.join(".gitignore"), b"ignored/\n").expect("gitignore");
            let mut ignore_permissions = fs::metadata(repo.join(".gitignore"))
                .expect("gitignore metadata")
                .permissions();
            ignore_permissions.set_mode(0o755);
            fs::set_permissions(repo.join(".gitignore"), ignore_permissions)
                .expect("chmod gitignore");
            git(&repo, &["add", "--all", "--force"]);
            commit(&repo, "initial exact tree");

            let gitlink_target = git_stdout(&repo, &["rev-parse", "HEAD"]);
            fs::create_dir_all(repo.join("vendor/dependency")).expect("gitlink directory");
            git(
                &repo,
                &[
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("160000,{gitlink_target},vendor/dependency"),
                ],
            );
            commit(&repo, "add gitlink leaf");

            fs::create_dir_all(repo.join("ignored")).expect("ignored directory");
            fs::write(repo.join("ignored/cache.bin"), b"cache\n").expect("ignored cache");
            let info_exclude = repo.join(".git/info/exclude");
            let mut info_body = fs::read(&info_exclude).unwrap_or_default();
            info_body.extend_from_slice(b"\nlocal.tmp\n");
            fs::write(&info_exclude, info_body).expect("info exclude");
            fs::write(repo.join("local.tmp"), b"local\n").expect("local ignored");
            let global_excludes = temp.path().join("global-ignore");
            fs::write(&global_excludes, b"global.tmp\n").expect("global ignore");
            git(
                &repo,
                &[
                    "config",
                    "core.excludesFile",
                    global_excludes.to_str().expect("utf8 test path"),
                ],
            );
            fs::write(repo.join("global.tmp"), b"global\n").expect("global ignored");

            git(
                &repo,
                &[
                    "remote",
                    "add",
                    "origin",
                    "https://example.invalid/private/repo.git",
                ],
            );
            git(
                &repo,
                &[
                    "remote",
                    "set-url",
                    "--add",
                    "origin",
                    "https://mirror.example.invalid/private/repo.git",
                ],
            );
            git(
                &repo,
                &[
                    "remote",
                    "set-url",
                    "--push",
                    "origin",
                    "ssh://example.invalid/private/repo.git",
                ],
            );
            git(
                &repo,
                &[
                    "remote",
                    "set-url",
                    "--add",
                    "--push",
                    "origin",
                    "ssh://mirror.example.invalid/private/repo.git",
                ],
            );
            git(
                &repo,
                &[
                    "config",
                    "--add",
                    "remote.origin.fetch",
                    "+refs/tags/*:refs/tags/*",
                ],
            );
            git(
                &repo,
                &[
                    "config",
                    "--add",
                    "remote.origin.push",
                    "refs/heads/main:refs/heads/main",
                ],
            );
            git(&repo, &["config", "branch.main.remote", "origin"]);
            git(&repo, &["config", "branch.main.merge", "refs/heads/main"]);
            git(&repo, &["config", "branch.main.pushRemote", "origin"]);
            git(&repo, &["config", "remote.pushDefault", "origin"]);
            git(&repo, &["config", "push.default", "simple"]);

            let store = BlobStore::new(temp.path().join("cas")).expect("blob store");
            let (snapshot, plan) = snapshot_plan(&repo, &store);
            Self {
                temp,
                repo,
                store,
                snapshot,
                plan,
            }
        }

        fn preflight(&self) -> Result<GitMigrationPreflightProof> {
            preflight_git_migration(&self.repo, &self.snapshot, &self.plan, &self.store)
        }
    }

    #[test]
    fn proves_clean_polyglot_non_code_raw_path_and_unmaterialized_gitlink_workspace() {
        let fixture = Fixture::clean();
        let proof = fixture.preflight().expect("clean preflight");

        assert_eq!(proof.head, fixture.snapshot.head);
        assert_eq!(proof.refs, fixture.snapshot.refs);
        assert_eq!(proof.index.entry_count, 8);
        assert!(!proof.index.sparse);
        assert_eq!(proof.tracked_worktree.entry_count, 8);
        assert_eq!(proof.tracked_worktree.gitlink_count, 1);
        assert_eq!(proof.tracked_worktree.host_unrepresentable_count, 0);
        assert!(proof
            .ignored_local
            .entries
            .iter()
            .any(|entry| entry.path.as_bytes() == b"ignored/cache.bin"));
        assert!(proof
            .ignored_local
            .entries
            .iter()
            .any(|entry| entry.path.as_bytes() == b"local.tmp"));
        assert!(proof
            .ignored_local
            .entries
            .iter()
            .any(|entry| entry.path.as_bytes() == b"global.tmp"));
        assert_eq!(proof.ignored_local.inputs.len(), 2);
        assert_eq!(
            proof.ignored_local.inputs[0].source_kind,
            GitLocalIgnoreSourceKind::ResolvedGlobalExcludes
        );
        assert_eq!(proof.ignored_local.inputs[0].body, b"global.tmp\n");
        assert_eq!(
            proof.ignored_local.inputs[1].source_kind,
            GitLocalIgnoreSourceKind::RepositoryInfoExclude
        );
        for input in &proof.ignored_local.inputs {
            assert_eq!(input.body_hash, digest(&input.body));
            assert_eq!(input.body_len, input.body.len() as u64);
        }
        assert!(proof.compatibility.other_registered_worktrees.is_empty());
        assert!(proof.compatibility.local_hooks.is_empty());
        assert!(proof.compatibility.checkout_filters.is_empty());
        assert_eq!(proof.remote_mapping.remotes.len(), 1);
        assert_eq!(proof.remote_mapping.remotes[0].name, b"origin");
        assert_eq!(
            proof.remote_mapping.remotes[0].fetch_urls,
            vec![
                b"https://example.invalid/private/repo.git".to_vec(),
                b"https://mirror.example.invalid/private/repo.git".to_vec(),
            ]
        );
        assert_eq!(
            proof.remote_mapping.remotes[0].push_urls,
            vec![
                b"ssh://example.invalid/private/repo.git".to_vec(),
                b"ssh://mirror.example.invalid/private/repo.git".to_vec(),
            ]
        );
        assert_eq!(
            proof.remote_mapping.remotes[0].fetch_refspecs,
            vec![
                b"+refs/heads/*:refs/remotes/origin/*".to_vec(),
                b"+refs/tags/*:refs/tags/*".to_vec(),
            ]
        );
        assert_eq!(
            proof.remote_mapping.remotes[0].push_refspecs,
            vec![b"refs/heads/main:refs/heads/main".to_vec()]
        );
        assert_eq!(proof.remote_mapping.branch_tracking.len(), 1);
        assert_eq!(
            proof.remote_mapping.branch_tracking[0].remote,
            Some(b"origin".to_vec())
        );
        assert_eq!(
            proof.remote_mapping.branch_tracking[0].merge_refs,
            vec![b"refs/heads/main".to_vec()]
        );
        assert_eq!(
            proof.remote_mapping.branch_tracking[0].push_remote,
            Some(b"origin".to_vec())
        );
        assert_eq!(
            proof.remote_mapping.remote_push_default,
            Some(b"origin".to_vec())
        );
        assert_eq!(proof.remote_mapping.push_default, Some(b"simple".to_vec()));
        let debug = format!("{proof:?}");
        assert!(!debug.contains("example.invalid"));
        assert!(!debug.contains("refs/heads/main"));
        assert!(debug.contains("<redacted>"));
        assert_ne!(
            proof.observation_fingerprint,
            digest(b"kin.git.preflight.unset")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn proves_host_unrepresentable_index_path_as_graph_only_absent() {
        let (temp, repo) = config_only_repository();
        fs::write(repo.join("README.md"), b"materialized\n").expect("README");
        git(&repo, &["add", "README.md"]);

        let blob_oid = String::from_utf8(
            git_stdin(
                &repo,
                &["hash-object", "-w", "--stdin"],
                "graph-only bytes\n",
            )
            .stdout,
        )
        .expect("blob oid")
        .trim()
        .to_string();
        let raw_path = b"opaque-\xff.bin";
        let mut cache_info = format!("100644,{blob_oid},").into_bytes();
        cache_info.extend_from_slice(raw_path);
        let arguments = [
            OsString::from("update-index"),
            OsString::from("--add"),
            OsString::from("--cacheinfo"),
            OsString::from_vec(cache_info),
        ];
        let output = git_command(&repo)
            .args(&arguments)
            .output()
            .expect("add raw index path");
        assert!(
            output.status.success(),
            "raw update-index failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        commit(&repo, "host-unrepresentable exact path");

        let store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let (snapshot, plan) = snapshot_plan(&repo, &store);
        assert!(plan
            .workspace_seed
            .base_tree
            .artifact_at_path(&RepoPath::from_bytes(raw_path.to_vec()).unwrap())
            .is_some());

        let proof =
            preflight_git_migration(&repo, &snapshot, &plan, &store).expect("exact preflight");
        assert_eq!(proof.index.entry_count, 2);
        assert_eq!(proof.tracked_worktree.entry_count, 2);
        assert_eq!(proof.tracked_worktree.host_unrepresentable_count, 1);
        assert_eq!(proof.tracked_worktree.gitlink_count, 0);
    }

    /// A baselined re-proof of an unchanged source agrees with its baseline,
    /// and both re-proof forms refuse the moment it does not.
    ///
    /// This is what pays for observing once instead of twice, so it is asserted
    /// on both entry points rather than assumed from one. The post-publication
    /// arm additionally has to accept the `.kin` publication installed, which is
    /// the only difference it is allowed to tolerate.
    #[test]
    fn a_baselined_reproof_agrees_with_its_baseline_and_refuses_any_drift() {
        let fixture = Fixture::clean();
        let baseline = fixture.preflight().expect("baseline proof");

        let agreed = reprove_git_migration(
            &fixture.repo,
            &baseline,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect("an unchanged source re-proves against its baseline");
        assert_eq!(agreed, baseline);

        let published_kin = fixture.repo.join(".kin");
        fs::create_dir(&published_kin).expect("published Kin directory");
        fs::write(published_kin.join("version"), b"6\n").expect("published Kin metadata");
        let after_publication = reprove_git_migration_after_publication(
            &fixture.repo,
            &published_kin,
            &baseline,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect("publication alone does not move the proof");
        assert_eq!(after_publication, baseline);

        // One tracked byte is enough, and it must refuse on both arms rather
        // than report the drift, because a single observation has no second
        // reading of its own to disagree with.
        fs::write(fixture.repo.join("compose.yaml"), b"services: {}\n")
            .expect("tracked source drift");
        let before_publication = reprove_git_migration(
            &fixture.repo,
            &baseline,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect_err("drift before publication is refused");
        assert!(
            before_publication
                .to_string()
                .contains("source proof changed"),
            "{before_publication}"
        );
        let across_publication = reprove_git_migration_after_publication(
            &fixture.repo,
            &published_kin,
            &baseline,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect_err("drift across publication is refused");
        assert!(
            across_publication
                .to_string()
                .contains("changed across repository publication"),
            "{across_publication}"
        );
    }

    /// A path that appears outside `.kin` after publication is still caught.
    ///
    /// The exclusion is the one thing the post-publication re-proof tolerates,
    /// so the test that matters is that it tolerates nothing beside it.
    #[test]
    fn a_baselined_post_publication_reproof_excludes_only_the_published_kin_directory() {
        let fixture = Fixture::clean();
        let baseline = fixture.preflight().expect("baseline proof");
        let published_kin = fixture.repo.join(".kin");
        fs::create_dir(&published_kin).expect("published Kin directory");
        fs::write(published_kin.join("version"), b"6\n").expect("published Kin metadata");
        fs::write(fixture.repo.join("outside-kin.txt"), b"untracked\n").expect("untracked sibling");

        let error = reprove_git_migration_after_publication(
            &fixture.repo,
            &published_kin,
            &baseline,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect_err("a path that appeared beside .kin is not excluded");
        assert!(
            error
                .to_string()
                .contains("changed across repository publication"),
            "{error}"
        );
    }

    /// A re-proof will not accept a baseline taken from a different plan.
    ///
    /// Skipping the structural plan rebuild rests on the plan being the one the
    /// baseline proved, and `semantic_plan_fingerprint` is what carries that.
    /// It is still derived on every observation, so a mismatched plan moves the
    /// proof and fails the comparison rather than passing unvalidated.
    #[test]
    fn a_baselined_reproof_refuses_a_baseline_from_another_plan() {
        let fixture = Fixture::clean();
        let mut baseline = fixture.preflight().expect("baseline proof");
        baseline.semantic_plan_fingerprint = digest(b"a plan this admission never proved");

        let error = reprove_git_migration(
            &fixture.repo,
            &baseline,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect_err("a baseline bound to another plan is refused");
        assert!(
            error.to_string().contains("source proof changed"),
            "{error}"
        );
    }

    #[test]
    fn post_publication_proof_excludes_only_the_exact_published_kin_directory() {
        let fixture = Fixture::clean();
        let before = fixture.preflight().expect("pre-publication proof");
        let published_kin = fixture.repo.join(".kin");
        fs::create_dir(&published_kin).expect("published Kin directory");
        fs::write(published_kin.join("version"), b"6\n").expect("published Kin metadata");

        let normal = fixture
            .preflight()
            .expect("ordinary preflight observes an ambient .kin");
        assert_discloses(
            &normal,
            ".kin/version",
            GitWorkspaceDivergenceKind::Untracked,
            "",
        );
        let after = preflight_git_migration_after_publication(
            &fixture.repo,
            &published_kin,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect("post-publication proof");
        assert_eq!(after, before);

        fs::write(fixture.repo.join("outside-kin.txt"), b"untracked\n").expect("untracked sibling");
        let sibling = preflight_git_migration_after_publication(
            &fixture.repo,
            &published_kin,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect("post-publication proof must retain all other worktree authority");
        assert_discloses(
            &sibling,
            "outside-kin.txt",
            GitWorkspaceDivergenceKind::Untracked,
            "",
        );
        assert_ne!(
            sibling, after,
            "a path that appeared after publication must change the proof"
        );
    }

    /// Tracked drift after publication is reported, and moves the proof.
    ///
    /// Init compares this proof against the one it took before publication and
    /// refuses on any difference, so reporting the drift rather than refusing it
    /// here keeps the same fail-closed outcome. Asserting the inequality is what
    /// proves that: a report the proof did not carry would leave the caller's
    /// comparison equal and the drift undetected.
    #[test]
    fn post_publication_proof_still_detects_tracked_source_drift() {
        let fixture = Fixture::clean();
        let published_kin = fixture.repo.join(".kin");
        fs::create_dir(&published_kin).expect("published Kin directory");
        fs::write(published_kin.join("version"), b"6\n").expect("published Kin metadata");
        let clean = preflight_git_migration_after_publication(
            &fixture.repo,
            &published_kin,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect("post-publication proof");
        assert_no_divergence(&clean);

        fs::write(fixture.repo.join("compose.yaml"), b"services: {}\n")
            .expect("tracked source drift");
        let drifted = preflight_git_migration_after_publication(
            &fixture.repo,
            &published_kin,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
        )
        .expect("tracked source drift is observed after publication");
        assert_discloses(
            &drifted,
            "compose.yaml",
            GitWorkspaceDivergenceKind::Modified,
            "bytes differ",
        );
        assert_ne!(drifted, clean, "drift must move the proof");
        assert_ne!(
            drifted.observation_fingerprint, clean.observation_fingerprint,
            "drift must move the observation fingerprint"
        );
    }

    #[test]
    fn rejects_materialized_gitlink_state_instead_of_silently_skipping_it() {
        let nested_marker = Fixture::clean();
        fs::write(
            nested_marker.repo.join("vendor/dependency/.git"),
            b"gitdir: nested-admin\n",
        )
        .expect("nested marker");
        assert_preflight_contains(&nested_marker, "materialized nested-repository state");

        let nested_worktree = Fixture::clean();
        fs::write(
            nested_worktree.repo.join("vendor/dependency/dirty.txt"),
            b"unmapped nested worktree\n",
        )
        .expect("nested file");
        assert_preflight_contains(&nested_worktree, "materialized nested-repository state");
    }

    /// Staged work is reported, not refused.
    ///
    /// An edit that was staged and one that was only announced with
    /// `git add -N` are both paths the operator has not committed, so both are
    /// workspace state rather than a reason the source cannot be read.
    #[test]
    fn reports_staged_and_intent_to_add_index_state() {
        let staged = Fixture::clean();
        fs::write(staged.repo.join("compose.yaml"), b"services: {}\n").expect("edit");
        git(&staged.repo, &["add", "compose.yaml"]);
        let proof = staged.preflight().expect("staged work is observed");
        assert_discloses(
            &proof,
            "compose.yaml",
            GitWorkspaceDivergenceKind::Staged,
            "not the committed one",
        );

        let intent = Fixture::clean();
        fs::write(intent.repo.join("intent.txt"), b"intent\n").expect("intent");
        git(&intent.repo, &["add", "--intent-to-add", "intent.txt"]);
        let proof = intent.preflight().expect("an announced path is observed");
        assert_discloses(
            &proof,
            "intent.txt",
            GitWorkspaceDivergenceKind::Staged,
            "does not carry this path",
        );
        // The index carries it, which is what Git calls tracked, so the worktree
        // walk must not report the same path a second time as untracked.
        assert_eq!(
            proof.workspace_divergence.entries.len(),
            1,
            "{:?}",
            proof.workspace_divergence
        );
    }

    /// An index Git has been told not to compare is still refused.
    ///
    /// Under these the index no longer states anything about the worktree, so an
    /// observation of one would not be an observation of the source at all. That
    /// is ambiguity about the source rather than uncommitted work, which is the
    /// line the in-progress-operation refusal already draws.
    #[test]
    fn rejects_conflicted_and_ambiguous_index_state() {
        let assume = Fixture::clean();
        git(
            &assume.repo,
            &["update-index", "--assume-unchanged", "compose.yaml"],
        );
        assert_preflight_contains(&assume, "ambiguous flags");

        let skipped = Fixture::clean();
        git(
            &skipped.repo,
            &["update-index", "--skip-worktree", "compose.yaml"],
        );
        assert_preflight_contains(&skipped, "ambiguous flags");

        let conflicted = Fixture::clean();
        let stage_zero = git_stdout(&conflicted.repo, &["ls-files", "-s", "src/main.rs"]);
        let oid = stage_zero
            .split_whitespace()
            .nth(1)
            .expect("index object id");
        git(
            &conflicted.repo,
            &["update-index", "--force-remove", "src/main.rs"],
        );
        let input = format!(
            "100644 {oid} 1\tsrc/main.rs\n100644 {oid} 2\tsrc/main.rs\n100644 {oid} 3\tsrc/main.rs\n"
        );
        git_stdin(&conflicted.repo, &["update-index", "--index-info"], &input);
        assert_preflight_contains(&conflicted, "conflict stage");

        let sparse = Fixture::clean();
        fs::write(sparse.repo.join(".git/info/sparse-checkout"), b"/src/\n")
            .expect("sparse marker");
        assert_preflight_contains(&sparse, "sparse checkout");
    }

    /// Every shape of worktree edit is observed and reported.
    ///
    /// None of it enters authority, which the clean case above already proves is
    /// the committed tree, so each one is workspace state whose only remaining
    /// question is whether init said so.
    #[test]
    fn reports_unstaged_untracked_mode_symlink_and_byte_mismatches() {
        let unstaged = Fixture::clean();
        fs::write(unstaged.repo.join("src/main.rs"), b"fn changed() {}\n").expect("edit");
        assert_discloses(
            &unstaged.preflight().expect("an edit is observed"),
            "src/main.rs",
            GitWorkspaceDivergenceKind::Modified,
            "bytes differ",
        );

        let untracked = Fixture::clean();
        fs::write(untracked.repo.join("surprise.txt"), b"surprise\n").expect("untracked");
        assert_discloses(
            &untracked
                .preflight()
                .expect("an untracked path is observed"),
            "surprise.txt",
            GitWorkspaceDivergenceKind::Untracked,
            "",
        );

        let executable = Fixture::clean();
        let mut permissions = fs::metadata(executable.repo.join("script.sh"))
            .expect("script metadata")
            .permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(executable.repo.join("script.sh"), permissions).expect("chmod");
        assert_discloses(
            &executable.preflight().expect("a mode change is observed"),
            "script.sh",
            GitWorkspaceDivergenceKind::Modified,
            "executable mode differs",
        );

        let symlink_target = Fixture::clean();
        fs::remove_file(symlink_target.repo.join("source-link")).expect("remove symlink");
        symlink(
            Path::new("compose.yaml"),
            symlink_target.repo.join("source-link"),
        )
        .expect("new symlink");
        assert_discloses(
            &symlink_target
                .preflight()
                .expect("a repointed link is observed"),
            "source-link",
            GitWorkspaceDivergenceKind::Modified,
            "link target differs",
        );

        let symlink_kind = Fixture::clean();
        fs::remove_file(symlink_kind.repo.join("source-link")).expect("remove symlink");
        fs::write(symlink_kind.repo.join("source-link"), b"src/main.rs").expect("regular file");
        assert_discloses(
            &symlink_kind
                .preflight()
                .expect("a replaced link is observed"),
            "source-link",
            GitWorkspaceDivergenceKind::Modified,
            "no longer materializes it as a symbolic link",
        );

        let removed = Fixture::clean();
        fs::remove_file(removed.repo.join("compose.yaml")).expect("remove tracked file");
        assert_discloses(
            &removed
                .preflight()
                .expect("a deleted committed path is observed"),
            "compose.yaml",
            GitWorkspaceDivergenceKind::Missing,
            "",
        );

        let unstaged_removal = Fixture::clean();
        git(&unstaged_removal.repo, &["rm", "--cached", "compose.yaml"]);
        assert_discloses(
            &unstaged_removal
                .preflight()
                .expect("a staged removal is observed"),
            "compose.yaml",
            GitWorkspaceDivergenceKind::StagedRemoval,
            "",
        );
    }

    /// A worked-in source seals authority at the committed tree regardless.
    ///
    /// This is the load-bearing half of admitting a dirty repository: the
    /// workspace seed the proof is bound to has to stay the committed tree, and
    /// the fingerprints of what was proven have to stay those of the clean
    /// source, so nothing uncommitted can reach repository authority through a
    /// path that merely stopped refusing.
    #[test]
    fn a_worked_in_source_still_seals_authority_at_the_committed_tree() {
        // One repository observed twice, because a second fixture commits its
        // own gitlink target and would differ for a reason this case is not
        // about.
        let fixture = Fixture::clean();
        let clean_proof = fixture.preflight().expect("clean preflight");

        fs::write(fixture.repo.join("src/main.rs"), b"fn edited() {}\n").expect("edit");
        fs::write(fixture.repo.join("surprise.txt"), b"surprise\n").expect("untracked");
        fs::write(fixture.repo.join("staged.txt"), b"staged\n").expect("staged");
        git(&fixture.repo, &["add", "staged.txt"]);
        let dirty_proof = fixture
            .preflight()
            .expect("a worked-in source is admissible");

        assert_eq!(
            dirty_proof.base_tree_hash, clean_proof.base_tree_hash,
            "authority is the committed tree, not the worktree"
        );
        assert_eq!(dirty_proof.head, clean_proof.head);
        assert_eq!(dirty_proof.base_target, clean_proof.base_target);
        assert_eq!(
            dirty_proof.snapshot_fingerprint, clean_proof.snapshot_fingerprint,
            "committed history is untouched by uncommitted work"
        );
        assert_eq!(
            dirty_proof.semantic_plan_fingerprint,
            clean_proof.semantic_plan_fingerprint
        );
        assert_eq!(
            dirty_proof.workspace_divergence.observed_paths(),
            3,
            "{:?}",
            dirty_proof.workspace_divergence
        );
        assert_ne!(
            dirty_proof.observation_fingerprint, clean_proof.observation_fingerprint,
            "what was observed must not fingerprint as a source that matched"
        );
    }

    #[test]
    fn reports_clean_status_checkout_transformations() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("source");
        fs::create_dir(&repo).expect("source");
        git(&repo, &["init", "--initial-branch=main"]);
        configure_identity(&repo);
        git(&repo, &["config", "core.autocrlf", "true"]);
        // The exact shape every Gradle and Maven wrapper project carries, so
        // the pattern this resolves is a glob rather than a literal name.
        fs::write(repo.join(".gitattributes"), b"*.bat text eol=crlf\n").expect("attributes");
        fs::write(repo.join("gradlew.bat"), b"line one\nline two\n").expect("text");
        git(&repo, &["add", "--all"]);
        commit(&repo, "crlf checkout");
        fs::remove_file(repo.join("gradlew.bat")).expect("remove text");
        git(&repo, &["checkout", "--", "gradlew.bat"]);
        assert!(fs::read(repo.join("gradlew.bat"))
            .expect("text bytes")
            .windows(2)
            .any(|pair| pair == b"\r\n"));
        assert_eq!(git_stdout(&repo, &["status", "--porcelain"]), "");

        let store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let (snapshot, plan) = snapshot_plan(&repo, &store);
        let proof = preflight_git_migration(&repo, &snapshot, &plan, &store)
            .expect("a rewritten checkout is observed");
        let reported = only_detail(&proof.workspace_divergence.entries);
        assert!(reported.contains("text eol=crlf"), "{reported}");
        assert!(reported.contains("line endings"), "{reported}");
        assert!(reported.contains("is not an unstaged edit"), "{reported}");
        assert!(!reported.contains("no checkout filter"), "{reported}");
        assert_discloses(
            &proof,
            "gradlew.bat",
            GitWorkspaceDivergenceKind::Modified,
            "line endings",
        );
    }

    /// A committed tree may record a mode the index cannot hold.
    ///
    /// `100664` is legal in a tree and several importers write it, while the
    /// index decodes every plain file to `100644`. Comparing the raw values
    /// reads such a repository as having every file staged, and no `git restore
    /// --staged` clears it because nothing is. The comparison runs on the entry
    /// kind for exactly this reason, and a repository that would have to answer
    /// for a report it cannot act on is what asserts it.
    #[test]
    fn a_non_canonical_committed_filemode_is_not_reported_as_staged() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("source");
        fs::create_dir(&repo).expect("source");
        git(&repo, &["init", "--initial-branch=main"]);
        configure_identity(&repo);
        pin_default_hook_surface(&repo);
        fs::write(repo.join("README.md"), b"seed\n").expect("readme");
        git(&repo, &["add", "--all"]);
        commit(&repo, "seed");

        let blob = git_stdout(&repo, &["rev-parse", "HEAD:README.md"]);
        // Written as raw tree bytes because `git mktree` canonicalises the mode
        // on the way in, which is exactly the normalisation this case needs to
        // be missing.
        let mut body = b"100664 README.md\0".to_vec();
        body.extend(
            (0..blob.len() / 2)
                .map(|index| u8::from_str_radix(&blob[index * 2..index * 2 + 2], 16))
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("hex object id"),
        );
        let tree = String::from_utf8(
            git_command(&repo)
                .args(["hash-object", "-t", "tree", "-w", "--stdin", "--literally"])
                .output_with_input(&body)
                .expect("write raw tree")
                .stdout,
        )
        .expect("utf8 object id")
        .trim()
        .to_string();
        let commit = String::from_utf8(
            git_stdin(
                &repo,
                &["commit-tree", &tree, "-m", "non-canonical mode"],
                "",
            )
            .stdout,
        )
        .expect("utf8 object id")
        .trim()
        .to_string();
        git(&repo, &["reset", "--hard", &commit]);
        // Read as raw object bytes, because `cat-file -p` prints the
        // canonicalised mode and would report the fixture worked either way.
        let raw = git_command(&repo)
            .args(["cat-file", "tree", "HEAD^{tree}"])
            .output()
            .expect("read raw committed tree");
        assert!(
            raw.stdout.starts_with(b"100664 "),
            "the fixture must keep the mode this case is about"
        );

        let store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let (snapshot, plan) = snapshot_plan(&repo, &store);
        let proof = preflight_git_migration(&repo, &snapshot, &plan, &store)
            .expect("a non-canonical mode is admissible");
        assert_no_divergence(&proof);
    }

    /// The partner of the checkout-transformation case above.
    ///
    /// A tree Git rewrote on checkout and a tree its operator edited both reach
    /// the same byte comparison, so the report is only useful if each names its
    /// own cause. Asserting that neither message carries the other's sentence is
    /// what keeps the two from collapsing back into one accusation.
    #[test]
    fn reports_unstaged_edits_without_blaming_a_checkout_filter() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("source");
        fs::create_dir(&repo).expect("source");
        git(&repo, &["init", "--initial-branch=main"]);
        configure_identity(&repo);
        git(&repo, &["config", "core.autocrlf", "false"]);
        fs::write(repo.join("text.txt"), b"line one\nline two\n").expect("text");
        git(&repo, &["add", "--all"]);
        commit(&repo, "committed text");
        fs::write(repo.join("text.txt"), b"line one\nline three\n").expect("edit");
        assert_ne!(git_stdout(&repo, &["status", "--porcelain"]), "");

        let store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let (snapshot, plan) = snapshot_plan(&repo, &store);
        let proof =
            preflight_git_migration(&repo, &snapshot, &plan, &store).expect("an edit is observed");
        assert_discloses(
            &proof,
            "text.txt",
            GitWorkspaceDivergenceKind::Modified,
            "no checkout filter",
        );
        let reported = only_detail(&proof.workspace_divergence.entries);
        assert!(!reported.contains("is not an unstaged edit"), "{reported}");
        assert!(!reported.contains(".gitattributes"), "{reported}");
        assert!(!reported.contains("line endings"), "{reported}");
    }

    #[test]
    fn rejects_operations_missing_index_missing_objects_and_shallow_state() {
        let operation = Fixture::clean();
        fs::write(
            operation.repo.join(".git/MERGE_HEAD"),
            b"0000000000000000000000000000000000000000\n",
        )
        .expect("merge marker");
        assert_preflight_contains(&operation, "operation Merge");

        let missing_index = Fixture::clean();
        fs::remove_file(missing_index.repo.join(".git/index")).expect("remove index");
        let error = missing_index
            .preflight()
            .expect_err("missing index must reject");
        assert!(error.to_string().contains("index"));

        let missing_object = Fixture::clean();
        let object = missing_object
            .snapshot
            .objects
            .iter()
            .find(|record| record.object.kind == ExternalObjectKind::Blob)
            .expect("blob object")
            .object
            .oid;
        let hex = object.to_string();
        fs::remove_file(
            missing_object
                .repo
                .join(".git/objects")
                .join(&hex[..2])
                .join(&hex[2..]),
        )
        .expect("remove loose object");
        let error = missing_object
            .preflight()
            .expect_err("missing object must reject");
        assert!(matches!(
            error,
            GitError::MissingObject { .. } | GitError::Git(_) | GitError::CorruptObject { .. }
        ));

        let shallow = Fixture::clean();
        let head = git_stdout(&shallow.repo, &["rev-parse", "HEAD"]);
        fs::write(shallow.repo.join(".git/shallow"), format!("{head}\n")).expect("shallow");
        assert!(matches!(
            shallow.preflight().expect_err("shallow rejection"),
            GitError::ShallowRepository
        ));
    }

    /// Naming the key must not name a credential the section header carries.
    #[test]
    fn an_unsupported_key_is_named_without_disclosing_its_section() {
        assert_eq!(printable_config_scope("branch.main"), "branch.main");
        assert_eq!(
            printable_config_scope("remote.https://user:s3cr3t@host/repo"),
            "remote"
        );

        let (temp, repo) = config_only_repository();
        let config = repo.join(".git/config");
        let mut body = fs::read(&config).expect("read config");
        body.extend_from_slice(
            b"\n[remote \"https://user:s3cr3t@host/repo\"]\n\ttagOpt = --tags\n",
        );
        fs::write(&config, body).expect("write config");
        fs::write(repo.join("README.md"), b"seed\n").expect("seed file");
        git(&repo, &["add", "README.md"]);
        commit(&repo, "seed");

        let store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let (snapshot, plan) = snapshot_plan(&repo, &store);
        let message = preflight_git_migration(&repo, &snapshot, &plan, &store)
            .expect_err("unsupported key must reject")
            .to_string();

        assert!(message.contains("tagOpt"), "{message}");
        assert!(!message.contains("s3cr3t"), "{message}");
    }

    #[test]
    fn returns_structured_hook_filter_and_worktree_blockers() {
        let hook = Fixture::clean();
        let hook_path = hook.repo.join(".git/hooks/pre-commit");
        fs::write(&hook_path, b"#!/bin/sh\nexit 0\n").expect("hook");
        let mut permissions = fs::metadata(&hook_path)
            .expect("hook metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&hook_path, permissions).expect("hook chmod");
        match hook.preflight().expect_err("hook blocker") {
            GitError::LocalCompatibilityBlockers {
                hook_count,
                hooks,
                filter_count,
                ..
            } => {
                assert_eq!(hook_count, 1);
                assert_eq!(filter_count, 0);
                assert_eq!(hooks[0].name, b"pre-commit");
                assert_eq!(stable_path(&hooks[0].path), stable_path(&hook_path));
                assert_eq!(
                    hooks[0].executable,
                    LocalGitHookExecutability::Executable,
                    "a chmod +x hook on a filesystem that records the bit is reported executable"
                );
            }
            error => panic!("unexpected error: {error:?}"),
        }

        let filter = Fixture::clean();
        git(
            &filter.repo,
            &["config", "filter.demo.clean", "external-clean"],
        );
        git(
            &filter.repo,
            &["config", "filter.demo.smudge", "external-smudge"],
        );
        match filter.preflight().expect_err("filter blocker") {
            GitError::LocalCompatibilityBlockers {
                hook_count,
                filters,
                filter_count,
                ..
            } => {
                assert_eq!(hook_count, 0);
                assert_eq!(filter_count, 1);
                assert_eq!(filters[0].name, b"demo");
                assert!(filters[0].clean_present);
                assert!(filters[0].smudge_present);
            }
            error => panic!("unexpected error: {error:?}"),
        }

        let custom_hooks = Fixture::clean();
        let custom_dir = custom_hooks.temp.path().join("custom-hooks");
        fs::create_dir_all(&custom_dir).expect("custom hooks directory");
        let redirected = custom_dir.join("pre-push");
        fs::write(&redirected, b"#!/bin/sh\nexit 0\n").expect("redirected hook");
        git(
            &custom_hooks.repo,
            &[
                "config",
                "core.hooksPath",
                custom_dir.to_str().expect("utf8 test path"),
            ],
        );
        match custom_hooks.preflight().expect_err("custom hooks blocker") {
            GitError::LocalCompatibilityBlockers {
                custom_hooks_path,
                hooks,
                ..
            } => {
                assert!(custom_hooks_path);
                assert_eq!(hooks.len(), 1);
                assert_eq!(hooks[0].name, b"pre-push");
                assert_eq!(stable_path(&hooks[0].path), stable_path(&redirected));
            }
            error => panic!("unexpected error: {error:?}"),
        }

        let worktrees = Fixture::clean();
        let other = worktrees.temp.path().join("other-worktree");
        git(
            &worktrees.repo,
            &[
                "worktree",
                "add",
                "--detach",
                other.to_str().expect("utf8 test path"),
            ],
        );
        let (snapshot, plan) = snapshot_plan(&worktrees.repo, &worktrees.store);
        let error = preflight_git_migration(&worktrees.repo, &snapshot, &plan, &worktrees.store)
            .expect_err("additional worktree blocker");
        let rendered = error.to_string();
        match error {
            GitError::AdditionalWorktrees { count, worktrees } => {
                assert_eq!(count, 1);
                assert_eq!(worktrees.len(), 1);
                assert_eq!(
                    stable_path(&worktrees[0].worktree.path),
                    stable_path(&other)
                );
                assert!(worktrees[0].reason.contains("detached HEAD"), "{rendered}");
                assert!(!worktrees[0].remedy.is_empty(), "{rendered}");
            }
            error => panic!("unexpected error: {error:?}"),
        }
        assert!(
            rendered.contains("other-worktree") && rendered.contains("detached HEAD"),
            "the refusal names the worktree and why: {rendered}"
        );
    }

    /// An idle sibling on a shared branch is proved, not refused.
    ///
    /// This is the shape every `git worktree` user has, and the one the fleet's
    /// own lane checkouts create. Its commits arrive through `refs/heads/*`
    /// like any other, so the capture misses nothing by admitting the source
    /// beside it.
    #[test]
    fn an_idle_linked_worktree_on_a_shared_branch_is_proved_and_recorded() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("idle-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "-b",
                "lane",
                other.to_str().expect("utf8 test path"),
            ],
        );

        let (snapshot, plan) = snapshot_plan(&fixture.repo, &fixture.store);
        let proof = preflight_git_migration(&fixture.repo, &snapshot, &plan, &fixture.store)
            .expect("an idle sibling worktree is tolerated");
        assert_eq!(proof.compatibility.other_registered_worktrees.len(), 1);
        assert_eq!(
            stable_path(&proof.compatibility.other_registered_worktrees[0].path),
            stable_path(&other)
        );
    }

    /// A sibling mid-rebase is refused, and only this check can see it.
    ///
    /// Its `rebase-merge` directory lives under `.git/worktrees/<id>`, which is
    /// neither the source's Git directory nor the common directory, so the
    /// source's own in-progress scan cannot reach it.
    #[test]
    fn a_linked_worktree_with_an_in_progress_operation_is_refused() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("rebasing-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "-b",
                "lane",
                other.to_str().expect("utf8 test path"),
            ],
        );
        let admin = fixture.repo.join(".git/worktrees/rebasing-worktree");
        assert!(admin.is_dir(), "fixture must own the worktree admin dir");
        fs::create_dir(admin.join("rebase-merge")).expect("in-progress rebase state");

        let (snapshot, plan) = snapshot_plan(&fixture.repo, &fixture.store);
        let rendered = preflight_git_migration(&fixture.repo, &snapshot, &plan, &fixture.store)
            .expect_err("a sibling mid-rebase is refused")
            .to_string();
        assert!(
            rendered.contains("rebasing-worktree") && rendered.contains("rebase-merge"),
            "the refusal names the worktree and its state: {rendered}"
        );
    }

    /// A sibling holding its own refs is refused, naming the ref.
    #[test]
    fn a_linked_worktree_holding_a_private_ref_is_refused() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("bisecting-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "-b",
                "lane",
                other.to_str().expect("utf8 test path"),
            ],
        );
        let private = fixture
            .repo
            .join(".git/worktrees/bisecting-worktree/refs/bisect");
        fs::create_dir_all(&private).expect("private ref directory");
        fs::write(
            private.join("bad"),
            b"0000000000000000000000000000000000000000\n",
        )
        .expect("private ref");

        let (snapshot, plan) = snapshot_plan(&fixture.repo, &fixture.store);
        let rendered = preflight_git_migration(&fixture.repo, &snapshot, &plan, &fixture.store)
            .expect_err("a sibling holding private refs is refused")
            .to_string();
        assert!(
            rendered.contains("bisecting-worktree") && rendered.contains("bisect"),
            "the refusal names the worktree and the ref: {rendered}"
        );
    }

    /// Init from inside a linked worktree tolerates an idle main worktree.
    ///
    /// The main sibling's git dir is the shared reference store, where every
    /// ordinary branch sits loose until a pack runs. A private-ref walk over
    /// that whole store reads the repository's own branches as the main
    /// checkout's private refs and refuses with a false reason, which is the
    /// defect this test pins: admission must not flip on pack state.
    #[test]
    fn init_from_a_linked_worktree_tolerates_an_idle_main_worktree() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("lane-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "-b",
                "lane",
                other.to_str().expect("utf8 test path"),
            ],
        );

        let (snapshot, plan) = snapshot_plan(&other, &fixture.store);
        let proof = preflight_git_migration(&other, &snapshot, &plan, &fixture.store)
            .expect("an idle main sibling with loose shared branches is tolerated");
        assert_eq!(proof.compatibility.other_registered_worktrees.len(), 1);
        assert_eq!(
            stable_path(&proof.compatibility.other_registered_worktrees[0].path),
            stable_path(&fixture.repo),
            "the tolerated sibling is the main worktree"
        );
    }

    /// Init from inside a linked worktree still refuses a main worktree
    /// mid-bisect, naming the per-worktree ref.
    #[test]
    fn init_from_a_linked_worktree_refuses_a_main_worktree_mid_bisect() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("lane-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "-b",
                "lane",
                other.to_str().expect("utf8 test path"),
            ],
        );
        let private = fixture.repo.join(".git/refs/bisect");
        fs::create_dir_all(&private).expect("main per-worktree ref directory");
        fs::write(
            private.join("bad"),
            b"0000000000000000000000000000000000000000\n",
        )
        .expect("main per-worktree ref");

        let (snapshot, plan) = snapshot_plan(&other, &fixture.store);
        let rendered = preflight_git_migration(&other, &snapshot, &plan, &fixture.store)
            .expect_err("a main sibling mid-bisect is refused")
            .to_string();
        assert!(
            rendered.contains("bisect"),
            "the refusal names the per-worktree ref: {rendered}"
        );
    }

    #[test]
    fn admits_the_only_linked_worktree_of_a_bare_repository() {
        let temp = tempfile::tempdir().expect("tempdir");
        let seed = temp.path().join("seed");
        fs::create_dir(&seed).expect("seed");
        git(&seed, &["init", "--initial-branch=main"]);
        configure_identity(&seed);
        fs::write(seed.join("README.md"), b"seed\n").expect("seed file");
        git(&seed, &["add", "README.md"]);
        commit(&seed, "seed");

        let bare = temp.path().join("common.git");
        git_at(
            temp.path(),
            &["init", "--bare", bare.to_str().expect("bare path")],
        );
        git_dir(
            &bare,
            &[
                "fetch",
                seed.to_str().expect("seed path"),
                "main:refs/heads/main",
            ],
        );
        git_dir(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        // The linked worktree resolves hooks through this common directory, so
        // the pin that keeps a developer host out of the answer belongs here.
        git_dir(
            &bare,
            &[
                "config",
                "core.hooksPath",
                bare.join("hooks").to_str().expect("bare hooks path"),
            ],
        );
        let linked = temp.path().join("linked");
        git_dir(
            &bare,
            &[
                "worktree",
                "add",
                linked.to_str().expect("linked path"),
                "main",
            ],
        );
        assert!(linked.join(".git").is_file());

        let store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let (snapshot, plan) = snapshot_plan(&linked, &store);
        let proof =
            preflight_git_migration(&linked, &snapshot, &plan, &store).expect("linked preflight");
        assert!(proof.compatibility.other_registered_worktrees.is_empty());
        assert_eq!(proof.tracked_worktree.entry_count, 1);
    }

    #[test]
    fn remote_value_drift_with_unchanged_counts_invalidates_preflight() {
        let fixture = Fixture::clean();
        let repo = fixture.repo.clone();
        let error = preflight_git_migration_with_hook(
            &fixture.repo,
            &fixture.snapshot,
            &fixture.plan,
            &fixture.store,
            None,
            None,
            move || {
                git(&repo, &["config", "--unset-all", "remote.origin.url"]);
                git(
                    &repo,
                    &[
                        "config",
                        "--add",
                        "remote.origin.url",
                        "https://changed.example.invalid/private/repo.git",
                    ],
                );
                git(
                    &repo,
                    &[
                        "config",
                        "--add",
                        "remote.origin.url",
                        "https://mirror.example.invalid/private/repo.git",
                    ],
                );
            },
        )
        .expect_err("same-count URL drift must invalidate the proof");
        let message = error.to_string();
        assert!(message.contains("changed during migration preflight"));
        assert!(!message.contains("changed.example.invalid"));
    }

    #[test]
    fn rejects_credentials_custom_schemes_and_transfer_overrides_without_disclosure() {
        let cases = [
            (
                "remote.origin.url",
                "https://super-secret@example.invalid/private/repo.git",
                "super-secret",
            ),
            (
                "remote.origin.url",
                "https://example.invalid/repo.git?token=super-secret",
                "super-secret",
            ),
            (
                "remote.origin.url",
                "https://example.invalid/repo.git#super-secret",
                "super-secret",
            ),
            (
                "remote.origin.url",
                "credential-helper://example.invalid/super-secret",
                "super-secret",
            ),
            ("credential.helper", "!super-secret", "super-secret"),
            (
                "http.extraHeader",
                "Authorization: super-secret",
                "super-secret",
            ),
            ("remote.origin.uploadpack", "super-secret", "super-secret"),
        ];

        for (case_index, (key, value, secret)) in cases.into_iter().enumerate() {
            let (temp, repo) = config_only_repository();
            git(
                &repo,
                &[
                    "remote",
                    "add",
                    "origin",
                    "https://example.invalid/repo.git",
                ],
            );
            git(&repo, &["config", "--replace-all", key, value]);
            let error = match remote_mapping_facts(&open_repo(&repo).expect("open config fixture"))
            {
                Ok(_) => panic!("unsafe transport config case {case_index} must reject"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(message.contains("safe exact subset"), "{message}");
            assert!(!message.contains(secret), "secret leaked in {message}");
            drop(temp);
        }

        let (temp, repo) = config_only_repository();
        git(
            &repo,
            &[
                "config",
                "url.https://rewritten.example.invalid/.insteadOf",
                "https://example.invalid/",
            ],
        );
        let error = remote_mapping_facts(&open_repo(&repo).expect("open rewrite fixture"))
            .expect_err("URL rewrite must reject");
        assert!(error.to_string().contains("safe exact subset"));
        drop(temp);

        let (temp, repo) = config_only_repository();
        let included = temp.path().join("included-config");
        fs::write(
            &included,
            b"[remote \"hidden\"]\nurl = https://example.invalid/\n",
        )
        .expect("included config");
        git(
            &repo,
            &[
                "config",
                "include.path",
                included.to_str().expect("UTF-8 test path"),
            ],
        );
        let error = remote_mapping_facts(&open_repo(&repo).expect("open include fixture"))
            .expect_err("local include must reject");
        assert!(error.to_string().contains("safe exact subset"));
    }

    /// A submodule is the one transfer-affecting section a user reaches without
    /// ever configuring transport: `git submodule add` writes it for them. The
    /// refusal is correct until submodule modeling lands, so the message is what
    /// has to carry the user from the failure to an action.
    #[test]
    fn submodule_rejection_names_the_submodule_its_path_and_the_workaround() {
        let (_temp, repo) = config_only_repository();
        git(
            &repo,
            &[
                "config",
                "submodule.vendor/anyhow.url",
                "https://example.invalid/anyhow.git",
            ],
        );
        let error = remote_mapping_facts(&open_repo(&repo).expect("open submodule fixture"))
            .expect_err("submodule config must reject");
        let message = error.to_string();

        assert!(
            message.contains("safe exact subset"),
            "the refusal itself is unchanged: {message}"
        );
        assert!(
            message.contains("submodule"),
            "must name the cause the user can recognize: {message}"
        );
        assert!(
            message.contains("vendor/anyhow"),
            "must name which submodule: {message}"
        );
        assert!(
            message.contains(".gitmodules"),
            "must name the file the entry lives in: {message}"
        );
        assert!(
            message.contains("git submodule deinit"),
            "must state the workaround: {message}"
        );
    }

    /// Every transfer-affecting section shares one message, so naming the cause
    /// means naming the section that actually matched rather than guessing.
    #[test]
    fn transfer_affecting_sections_name_the_section_that_matched() {
        for (key, value, expected) in [
            ("http.postBuffer", "1048576", "http"),
            ("credential.helper", "cache", "credential"),
            ("lfs.url", "https://example.invalid/lfs", "lfs"),
        ] {
            let (temp, repo) = config_only_repository();
            git(&repo, &["config", key, value]);
            let error = remote_mapping_facts(&open_repo(&repo).expect("open section fixture"))
                .expect_err("transfer-affecting section must reject");
            let message = error.to_string();
            assert!(message.contains("safe exact subset"), "{message}");
            assert!(
                message.contains(expected),
                "must name the [{expected}] section: {message}"
            );
            drop(temp);
        }
    }

    /// The falsification for naming things. A section name is one of a fixed set
    /// of literals and is always safe to print; a subsection name is arbitrary
    /// user bytes, and for `url`, `http`, and `credential` it IS a URL that can
    /// carry `user:password@`. Naming the cause must never turn an error message
    /// into a credential disclosure.
    #[test]
    fn naming_the_section_never_echoes_a_credential_bearing_subsection() {
        let (temp, repo) = config_only_repository();
        git(
            &repo,
            &[
                "config",
                "url.https://kin:hunter2@example.invalid/.insteadOf",
                "https://example.invalid/",
            ],
        );
        let error = remote_mapping_facts(&open_repo(&repo).expect("open rewrite fixture"))
            .expect_err("URL rewrite must reject");
        let message = error.to_string();
        assert!(
            message.contains("url"),
            "must still name the section: {message}"
        );
        assert!(
            !message.contains("hunter2"),
            "credential leaked into the refusal: {message}"
        );
        drop(temp);

        // A submodule's own URL lives in a key inside the section, never in the
        // subsection name, so naming the path cannot disclose it.
        let (_temp, repo) = config_only_repository();
        git(
            &repo,
            &[
                "config",
                "submodule.vendor/dep.url",
                "https://kin:hunter2@example.invalid/dep.git",
            ],
        );
        let error = remote_mapping_facts(&open_repo(&repo).expect("open submodule url fixture"))
            .expect_err("submodule config must reject");
        let message = error.to_string();
        assert!(message.contains("vendor/dep"), "{message}");
        assert!(
            !message.contains("hunter2"),
            "credential leaked into the refusal: {message}"
        );
    }

    /// A submodule path that is not valid UTF-8 has no spelling the message can
    /// safely carry, so the section is still named and the path is simply
    /// omitted. The refusal must not become an error about printing.
    #[test]
    fn a_non_utf8_submodule_path_still_refuses_and_still_names_the_section() {
        let (_temp, repo) = config_only_repository();
        let config = repo.join(".git/config");
        let mut bytes = fs::read(&config).expect("read config");
        bytes.extend_from_slice(b"[submodule \"vendor/\xff\"]\n\turl = https://example.invalid/\n");
        fs::write(&config, bytes).expect("write config");

        let error = remote_mapping_facts(&open_repo(&repo).expect("open non-utf8 fixture"))
            .expect_err("submodule config must reject");
        let message = error.to_string();
        assert!(message.contains("safe exact subset"), "{message}");
        assert!(message.contains("submodule"), "{message}");
    }

    #[test]
    fn rejects_non_utf8_remote_names_and_values() {
        let (_temp, repo) = config_only_repository();
        let config_path = repo.join(".git/config");
        let mut config = fs::OpenOptions::new()
            .append(true)
            .open(&config_path)
            .expect("open local config");
        config
            .write_all(b"\n[remote \"raw-\xff\"]\n\turl = https://example.invalid/repo.git\n")
            .expect("append raw config");
        drop(config);

        let outcome = open_repo(&repo).and_then(|repo| remote_mapping_facts(&repo));
        assert!(outcome.is_err(), "non-UTF-8 remote name must fail closed");
    }

    #[test]
    fn absent_index_is_admitted_only_for_a_truly_unborn_empty_workspace() {
        let (temp, repo) = config_only_repository();
        assert!(!repo.join(".git/index").exists());
        let store = BlobStore::new(temp.path().join("cas")).expect("blob store");
        let (snapshot, plan) = snapshot_plan(&repo, &store);

        let proof =
            preflight_git_migration(&repo, &snapshot, &plan, &store).expect("unborn preflight");
        assert!(!proof.index.present);
        assert_eq!(proof.index.entry_count, 0);
        assert!(proof.base_target.is_none());
        assert!(proof.base_commit_oid.is_none());
        assert!(proof.base_tree_hash.is_none());

        let (born_temp, born_repo) = config_only_repository();
        git(
            &born_repo,
            &[
                "commit",
                "--allow-empty",
                "--no-gpg-sign",
                "-m",
                "born empty",
            ],
        );
        assert!(born_repo.join(".git/index").is_file());
        let born_store = BlobStore::new(born_temp.path().join("cas")).expect("born blob store");
        let (born_snapshot, born_plan) = snapshot_plan(&born_repo, &born_store);
        assert!(born_plan.workspace_seed.base_target.is_some());
        assert!(born_plan.workspace_seed.base_tree_hash.is_some());
        assert!(born_plan.workspace_seed.base_tree.is_empty());
        fs::remove_file(born_repo.join(".git/index")).expect("remove born empty index");
        let error = preflight_git_migration(&born_repo, &born_snapshot, &born_plan, &born_store)
            .expect_err("born empty repository without an index must reject");
        assert!(error.to_string().contains("index"));
    }

    #[test]
    fn fails_when_source_or_local_ignore_inputs_change_during_preflight() {
        let source_change = Fixture::clean();
        let repo = source_change.repo.clone();
        let error = preflight_git_migration_with_hook(
            &source_change.repo,
            &source_change.snapshot,
            &source_change.plan,
            &source_change.store,
            None,
            None,
            move || {
                fs::write(repo.join("ignored/new-cache"), b"new\n").expect("TOCTOU file");
            },
        )
        .expect_err("source TOCTOU");
        assert!(error
            .to_string()
            .contains("changed during migration preflight"));

        let ignore_change = Fixture::clean();
        let info_exclude = ignore_change.repo.join(".git/info/exclude");
        let error = preflight_git_migration_with_hook(
            &ignore_change.repo,
            &ignore_change.snapshot,
            &ignore_change.plan,
            &ignore_change.store,
            None,
            None,
            move || {
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(info_exclude)
                    .expect("open info exclude");
                file.write_all(b"later.tmp\n").expect("append ignore");
            },
        )
        .expect_err("ignore-input TOCTOU");
        assert!(error
            .to_string()
            .contains("changed during migration preflight"));
    }

    fn snapshot_plan(
        repo: &Path,
        store: &BlobStore,
    ) -> (LosslessGitRepository, SemanticGitImportPlan) {
        let repository_id = RepositoryId::new("preflight-test").expect("repository id");
        let snapshot =
            capture_lossless_git_repository(repo, repository_id, store).expect("capture");
        let plan = plan_semantic_git_import(&snapshot, store).expect("plan");
        (snapshot, plan)
    }

    fn config_only_repository() -> (TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("source");
        fs::create_dir(&repo).expect("source directory");
        git(&repo, &["init", "--initial-branch=main"]);
        configure_identity(&repo);
        (temp, repo)
    }

    fn assert_preflight_contains(fixture: &Fixture, expected: &str) {
        let error = fixture.preflight().expect_err("preflight must reject");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in {error:?}"
        );
    }

    /// One path reported as diverging, of the expected kind and reason.
    ///
    /// Asserts the proof was produced at all, which is the half that would
    /// silently disappear if the observation went back to refusing.
    fn assert_discloses(
        proof: &GitMigrationPreflightProof,
        path: &str,
        kind: GitWorkspaceDivergenceKind,
        detail: &str,
    ) {
        let divergence = &proof.workspace_divergence;
        let found = divergence
            .entries
            .iter()
            .find(|entry| entry.path.to_string() == path && entry.kind == kind)
            .unwrap_or_else(|| {
                panic!("{path} is not reported as {}: {divergence:?}", kind.label())
            });
        assert!(
            found.detail.contains(detail),
            "expected {detail:?} in {found:?}"
        );
    }

    /// The one sentence a single reported divergence carries.
    fn only_detail(entries: &[GitWorkspaceDivergence]) -> String {
        let [entry] = entries else {
            panic!("expected exactly one divergence, got {entries:?}");
        };
        entry.detail.clone()
    }

    fn assert_no_divergence(proof: &GitMigrationPreflightProof) {
        assert!(
            proof.workspace_divergence.is_empty(),
            "unexpected divergence: {:?}",
            proof.workspace_divergence
        );
    }

    fn configure_identity(repo: &Path) {
        git(repo, &["config", "user.name", "Kin Test"]);
        git(repo, &["config", "user.email", "kin@example.invalid"]);
        git(repo, &["config", "commit.gpgSign", "false"]);
        pin_default_hook_surface(repo);
    }

    /// Bind a fixture's hook surface to its own `.git/hooks`.
    ///
    /// Hook resolution reads the merged Git configuration, and this process is
    /// not the isolated Git child a fixture launches, so a developer host that
    /// sets `core.hooksPath` globally redirects a fixture too. Repository scope
    /// outranks the host, so pinning it here settles what every case reads.
    fn pin_default_hook_surface(repo: &Path) {
        let hooks = repo.join(".git/hooks");
        fs::create_dir_all(&hooks).expect("default hook directory");
        git(
            repo,
            &[
                "config",
                "core.hooksPath",
                hooks.to_str().expect("utf8 test path"),
            ],
        );
    }

    fn commit(repo: &Path, message: &str) {
        git(
            repo,
            &[
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-m",
                message,
                "--no-gpg-sign",
            ],
        );
    }

    fn git(repo: &Path, args: &[&str]) -> Output {
        let output = git_command(repo).args(args).output().expect("run git");
        assert_git_success(args, &output);
        output
    }

    fn git_at(directory: &Path, args: &[&str]) -> Output {
        let output = git_command(directory).args(args).output().expect("run git");
        assert_git_success(args, &output);
        output
    }

    fn git_dir(git_dir: &Path, args: &[&str]) -> Output {
        let output = clean_git_command()
            .arg("--git-dir")
            .arg(git_dir)
            .args(args)
            .output()
            .expect("run git-dir command");
        assert_git_success(args, &output);
        output
    }

    fn git_stdout(repo: &Path, args: &[&str]) -> String {
        String::from_utf8(git(repo, args).stdout)
            .expect("utf8 git stdout")
            .trim()
            .to_string()
    }

    fn git_stdin(repo: &Path, args: &[&str], input: &str) -> Output {
        let output = git_command(repo)
            .args(args)
            .output_with_input(input.as_bytes())
            .expect("spawn git");
        assert_git_success(args, &output);
        output
    }

    fn git_command(repo: &Path) -> FixtureGitCommand {
        let mut command = clean_git_command();
        command.current_dir(repo);
        command
    }

    fn clean_git_command() -> FixtureGitCommand {
        fixture_git()
    }

    fn assert_git_success(args: &[&str], output: &Output) {
        assert!(
            output.status.success(),
            "git {args:?} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
