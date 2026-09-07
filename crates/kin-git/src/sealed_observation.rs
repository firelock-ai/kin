// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Sealed all-content observation over an admitted repository closure.
//!
//! Exact Git admission proves that the reachable object closure is captured
//! atomically. That is a statement about Git objects, not about the repository
//! content those objects resolve to. Nothing in the object walk asserts that
//! the trees Kin actually answers from are content-complete in graph-owned
//! storage; that has held only because the tree decoder and the authority copy
//! happen to agree on the same body identity.
//!
//! This boundary makes the guarantee explicit. It walks every admitted tree,
//! classifies every entry by its exact shape, and proves that every
//! content-bearing entry resolves to a byte-exact body the graph already owns.
//!
//! Content is read only through the supplied graph-owned source; the
//! filesystem is never consulted. A repository that seals here can answer for
//! its admitted content without a raw file read. Shapes whose content is
//! genuinely foreign are declared as explicit exclusions rather than skipped,
//! and any entry that cannot be sealed fails admission with an enumerated gap
//! report instead of degrading into a filesystem fallback.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use kin_blobs::digest;
#[cfg(test)]
use kin_blobs::BlobStore;
use kin_model::{GitObjectId, Hash256, RepoPath, RepositoryId, ResolvedTree, TreeEntry};

use crate::admission_history::AdmittedSemanticGitImportPlan;
use crate::error::{GitError, Result, UnsealedContentGap};
use crate::semantic_import::SemanticGitImportPlan;

/// Upper bound on gaps carried in a failure. A gap is one distinct unsealed
/// body, counted once no matter how many admitted entries reference it, so the
/// reported total and the detail list count the same thing. Only the detail
/// list is bounded, so a repository with a systematically empty store produces
/// a readable error rather than one entry per artifact in its entire history.
const MAX_REPORTED_GAPS: usize = 32;

/// Shape tags bound into the per-tree content digest. An entry's shape is part
/// of what the repository owns, so a body that moves between a regular file, an
/// executable, and a symlink is a different observation even at the same path.
const SHAPE_REGULAR_FILE: u8 = 1;
const SHAPE_EXECUTABLE_FILE: u8 = 2;
const SHAPE_SYMLINK: u8 = 3;
const SHAPE_FOREIGN_GITLINK: u8 = 4;

/// Graph-owned content the observation is permitted to read.
///
/// The observation deliberately cannot reach the filesystem. Implementations
/// expose exactly one capability: resolve a content identity to bytes the
/// repository already owns.
pub trait SealedContentSource {
    /// Load one body by its content identity.
    ///
    /// `Err` denotes an absent or unreadable body. The caller turns that into a
    /// reported gap rather than an immediate abort, so a single seal reports
    /// every gap it found instead of only the first.
    fn load_sealed_content(&self, digest: Hash256) -> std::result::Result<Vec<u8>, String>;
}

// Sealing against a bare content store proves byte-exactness but says nothing
// about graph ownership, so this impl exists only for fixtures that need a real
// store behind the observation. Product paths must seal against repository
// authority; gating the impl keeps the weaker source from compiling into one.
#[cfg(test)]
impl SealedContentSource for BlobStore {
    fn load_sealed_content(&self, digest: Hash256) -> std::result::Result<Vec<u8>, String> {
        self.read(&digest).map_err(|error| error.to_string())
    }
}

/// What one admitted tree contributes to the sealed observation, taken once
/// while the tree was live.
///
/// The digest binds the tree's exact (path, shape, body) sequence, so two
/// closures that agree on every count but place different bodies at different
/// paths still fingerprint apart. The tallies are what the observation sums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedTreeObservation {
    pub entries: usize,
    pub regular_file_entries: usize,
    pub executable_file_entries: usize,
    pub symlink_entries: usize,
    pub gitlink_entries: usize,
    pub digest: Hash256,
}

/// Everything the sealed all-content observation reads from a closure's
/// commit trees, without the trees.
///
/// A conversion used to keep every commit's exact tree alive so this
/// observation could walk them at phases 10 and 17, which is one map over
/// every artifact in the repository per commit in its history. Each tree is
/// walked here instead at the moment the derivation resolves it, and what the
/// walk keeps is a digest and five counters per commit, plus one entry per
/// distinct content identity, non-UTF-8 path and foreign gitlink the trees
/// reference between them. The seal proves the same bodies it always proved,
/// from the same trees, and fingerprints to the same value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdmittedContentSummary {
    /// One observation per imported commit tree, keyed by commit.
    pub trees: BTreeMap<GitObjectId, SealedTreeObservation>,
    /// Every distinct content identity some commit tree references, with the
    /// first path the derivation saw it at, so a gap can be reported by path.
    pub identities: BTreeMap<Hash256, RepoPath>,
    /// Distinct observed paths this host cannot name as UTF-8.
    pub non_utf8_paths: BTreeSet<RepoPath>,
    /// Content the observation declares rather than owns, by path and target.
    pub exclusions: BTreeMap<(RepoPath, GitObjectId), DeclaredContentExclusion>,
}

impl AdmittedContentSummary {
    /// Observe one commit's exact tree and keep what the seal needs of it.
    pub fn observe_commit_tree(
        &mut self,
        oid: GitObjectId,
        tree: &ResolvedTree,
    ) -> Result<SealedTreeObservation> {
        let observation = observe_tree_content(
            tree,
            &mut self.identities,
            &mut self.non_utf8_paths,
            &mut self.exclusions,
        );
        if self.trees.insert(oid, observation.clone()).is_some() {
            return Err(GitError::InvalidSnapshot(format!(
                "commit {oid} was observed twice for the sealed content observation"
            )));
        }
        Ok(observation)
    }
}

/// Observe one exact tree: its digest and entry tally, and the identities,
/// paths and exclusions it adds to the sets every tree shares.
pub(crate) fn observe_tree_content(
    tree: &ResolvedTree,
    identities: &mut BTreeMap<Hash256, RepoPath>,
    non_utf8_paths: &mut BTreeSet<RepoPath>,
    exclusions: &mut BTreeMap<(RepoPath, GitObjectId), DeclaredContentExclusion>,
) -> SealedTreeObservation {
    let mut observation = SealedTreeObservation {
        entries: 0,
        regular_file_entries: 0,
        executable_file_entries: 0,
        symlink_entries: 0,
        gitlink_entries: 0,
        digest: Hash256::from_bytes([0; 32]),
    };
    // One digest per admitted tree over its exact (path, shape, body)
    // sequence. Counts alone cannot distinguish two closures that agree on
    // totals but describe different content, so the observed content itself
    // is what the fingerprint ends up binding.
    let mut tree_content = Vec::new();
    tree_content.extend_from_slice(b"kin.git.sealed-content-observation.tree.v1\0");
    for artifact in tree.artifacts_by_path() {
        observation.entries += 1;
        let path = &artifact.path;
        if path.as_utf8().is_none() {
            non_utf8_paths.insert(path.clone());
        }
        append_bytes(&mut tree_content, path.as_bytes());
        let identity = match artifact.entry {
            TreeEntry::Blob { hash, executable } => {
                if executable {
                    observation.executable_file_entries += 1;
                    tree_content.push(SHAPE_EXECUTABLE_FILE);
                } else {
                    observation.regular_file_entries += 1;
                    tree_content.push(SHAPE_REGULAR_FILE);
                }
                append_bytes(&mut tree_content, hash.as_bytes());
                hash
            }
            TreeEntry::Symlink { target_blob } => {
                observation.symlink_entries += 1;
                tree_content.push(SHAPE_SYMLINK);
                append_bytes(&mut tree_content, target_blob.as_bytes());
                target_blob
            }
            TreeEntry::Gitlink { target } => {
                observation.gitlink_entries += 1;
                tree_content.push(SHAPE_FOREIGN_GITLINK);
                append_bytes(&mut tree_content, target.to_string().as_bytes());
                exclusions.entry((path.clone(), target)).or_insert_with(|| {
                    DeclaredContentExclusion {
                        path: path.clone(),
                        reason: ContentExclusionReason::ForeignGitlinkTarget { target },
                    }
                });
                continue;
            }
        };
        identities.entry(identity).or_insert_with(|| path.clone());
    }
    observation.digest = digest(&tree_content);
    observation
}

/// An admitted closure whose content can be sealed.
///
/// Implemented by the exact import plan, the closure that outlives its bodies
/// and the admitted form, so the same observation can be derived from any of
/// them and the results compared, rather than assuming they agree. None of
/// them holds a tree per commit: what each carries is the summary the
/// derivation took from every commit tree as it resolved it, and the one tree
/// the workspace seed admits.
pub trait AdmittedContentClosure {
    fn closure_repository_id(&self) -> &RepositoryId;
    /// What every imported commit tree contributed, in commit order, and the
    /// sets those trees reference between them.
    fn admitted_content(&self) -> Cow<'_, AdmittedContentSummary>;
    /// The workspace seed tree, observed after every commit tree.
    fn admitted_seed_tree(&self) -> &ResolvedTree;
}

impl AdmittedContentClosure for SemanticGitImportPlan {
    fn closure_repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }

    fn admitted_content(&self) -> Cow<'_, AdmittedContentSummary> {
        Cow::Borrowed(&self.content)
    }

    fn admitted_seed_tree(&self) -> &ResolvedTree {
        &self.workspace_seed.base_tree
    }
}

impl AdmittedContentClosure for crate::semantic_import::ProvedImportClosure {
    fn closure_repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }

    fn admitted_content(&self) -> Cow<'_, AdmittedContentSummary> {
        Cow::Borrowed(&self.content)
    }

    fn admitted_seed_tree(&self) -> &ResolvedTree {
        &self.workspace_seed.base_tree
    }
}

impl AdmittedContentClosure for AdmittedSemanticGitImportPlan {
    fn closure_repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }

    fn admitted_content(&self) -> Cow<'_, AdmittedContentSummary> {
        Cow::Borrowed(&self.content)
    }

    fn admitted_seed_tree(&self) -> &ResolvedTree {
        &self.workspace_seed.base_tree
    }
}

/// Coverage of one sealed all-content observation.
///
/// Entry counters are per tree occurrence, so a path present at every commit is
/// counted at every commit. Body counters are over distinct content identities,
/// because sealing proves a body once no matter how many trees reference it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealedContentCoverage {
    pub regular_file_entries: usize,
    pub executable_file_entries: usize,
    pub symlink_entries: usize,
    pub gitlink_entries: usize,
    /// Distinct content identities proven present and byte-exact in the graph.
    pub sealed_bodies: usize,
    pub sealed_body_bytes: u64,
    /// Distinct sealed bodies with no content. An empty file is exactly
    /// versioned like any other; it is counted so an all-empty seal cannot be
    /// mistaken for a complete one.
    pub empty_bodies: usize,
    /// Distinct sealed bodies that are not valid UTF-8. No semantic entity
    /// enrichment is expected of them and none is fabricated; they stay exactly
    /// versioned by content, path, and mode.
    pub opaque_bodies: usize,
    /// Distinct observed paths this host cannot name as UTF-8. They remain
    /// graph-owned and byte-exact regardless of host representability.
    pub non_utf8_paths: usize,
}

/// Content the observation intentionally does not own, declared rather than
/// silently skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredContentExclusion {
    pub path: RepoPath,
    pub reason: ContentExclusionReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentExclusionReason {
    /// A submodule pointer. The commit it names belongs to a different
    /// repository, so this repository seals the pointer exactly and owns no
    /// body for it. No entity is fabricated for the absent content.
    ForeignGitlinkTarget { target: GitObjectId },
}

/// Proof that every content-bearing entry of an admitted closure resolves to a
/// byte-exact body the graph owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContentObservation {
    pub repository_id: RepositoryId,
    /// Admitted trees observed: one per imported commit, plus the workspace
    /// seed tree.
    pub observed_trees: usize,
    pub observed_entries: usize,
    pub coverage: SealedContentCoverage,
    pub exclusions: Vec<DeclaredContentExclusion>,
    pub fingerprint: Hash256,
}

/// Prove sealed all-content observation over an admitted closure.
///
/// Every entry of every admitted tree is classified and, when it carries
/// content, proven present and byte-exact in `content`. Bodies are verified
/// against their recorded identity here rather than trusting the source to have
/// verified them, so the proof stands on its own.
///
/// Fails closed with every gap it found. A partial observation is never
/// returned, and no gap is ever repaired from the filesystem.
pub fn seal_all_content_observation(
    closure: &impl AdmittedContentClosure,
    content: &impl SealedContentSource,
) -> Result<SealedContentObservation> {
    seal_all_content_observation_observed(closure, content, &mut |_, _| {})
}

/// Prove sealed all-content observation, reporting progress as it goes.
///
/// The trees were observed when the derivation resolved them, so what remains
/// here is the body proof: every distinct content identity the admitted trees
/// reference is loaded from `content` and checked against that identity, once
/// whatever number of trees reference it. `observe` is called with
/// `(bodies_proved, bodies_total)` after each body so a caller can show that
/// the proof is advancing. It changes nothing the observation proves:
/// [`seal_all_content_observation`] is this function with an observer that
/// does nothing.
pub fn seal_all_content_observation_observed(
    closure: &impl AdmittedContentClosure,
    content: &impl SealedContentSource,
    observe: &mut dyn FnMut(usize, usize),
) -> Result<SealedContentObservation> {
    let summary = closure.admitted_content();
    // The workspace seed tree is observed after every commit tree, into the
    // same sets, which is the order the trees were walked in when every one
    // of them was walked here.
    let mut identities = summary.identities.clone();
    let mut non_utf8_paths = summary.non_utf8_paths.clone();
    let mut exclusions = summary.exclusions.clone();
    let seed = observe_tree_content(
        closure.admitted_seed_tree(),
        &mut identities,
        &mut non_utf8_paths,
        &mut exclusions,
    );

    let mut coverage = SealedContentCoverage::default();
    let mut observed_entries = 0usize;
    let mut tree_digests = Vec::with_capacity(summary.trees.len() + 1);
    for tree in summary.trees.values().chain(std::iter::once(&seed)) {
        observed_entries += tree.entries;
        coverage.regular_file_entries += tree.regular_file_entries;
        coverage.executable_file_entries += tree.executable_file_entries;
        coverage.symlink_entries += tree.symlink_entries;
        coverage.gitlink_entries += tree.gitlink_entries;
        tree_digests.push(tree.digest);
    }
    let observed_trees = summary.trees.len() + 1;

    let total_bodies = identities.len();
    let mut failed = BTreeSet::<Hash256>::new();
    let mut reported_gaps = Vec::<UnsealedContentGap>::new();
    for (proved, (identity, path)) in identities.iter().enumerate() {
        match seal_body(content, *identity) {
            Ok(body) => {
                coverage.sealed_bodies += 1;
                coverage.sealed_body_bytes += body.len() as u64;
                if body.is_empty() {
                    coverage.empty_bodies += 1;
                }
                if std::str::from_utf8(&body).is_err() {
                    coverage.opaque_bodies += 1;
                }
            }
            Err(detail) => {
                failed.insert(*identity);
                if reported_gaps.len() < MAX_REPORTED_GAPS {
                    reported_gaps.push(UnsealedContentGap {
                        path: path.as_bytes().to_vec(),
                        expected: identity.to_string(),
                        detail,
                    });
                }
            }
        }
        observe(proved + 1, total_bodies);
    }

    // One gap per distinct unsealed body, so a report that lists every gap it
    // found is never described as truncated.
    if !failed.is_empty() {
        return Err(GitError::UnsealedContent {
            total_gaps: failed.len(),
            reported: reported_gaps,
        });
    }

    coverage.non_utf8_paths = non_utf8_paths.len();
    let exclusions = exclusions.into_values().collect::<Vec<_>>();
    let repository_id = closure.closure_repository_id().clone();
    let fingerprint = fingerprint_observation(
        &repository_id,
        observed_trees,
        observed_entries,
        &coverage,
        &exclusions,
        &tree_digests,
    );
    Ok(SealedContentObservation {
        repository_id,
        observed_trees,
        observed_entries,
        coverage,
        exclusions,
        fingerprint,
    })
}

/// Read one body and prove it matches the identity the tree recorded.
fn seal_body(
    content: &impl SealedContentSource,
    identity: Hash256,
) -> std::result::Result<Vec<u8>, String> {
    let body = content.load_sealed_content(identity)?;
    let observed = digest(&body);
    if observed != identity {
        return Err(format!(
            "graph-owned body hashes to {observed}, but the admitted tree requires {identity}"
        ));
    }
    Ok(body)
}

/// Bind one observation to a single identity.
///
/// The digest covers the observed content itself, not only how much of it there
/// was: `tree_content_digests` carries the exact (path, shape, body) sequence of
/// every admitted tree, in admission order. Two observations therefore
/// fingerprint identically only when they describe the same content, which is
/// what lets one derivation be cross-checked against another.
fn fingerprint_observation(
    repository_id: &RepositoryId,
    observed_trees: usize,
    observed_entries: usize,
    coverage: &SealedContentCoverage,
    exclusions: &[DeclaredContentExclusion],
    tree_content_digests: &[Hash256],
) -> Hash256 {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"kin.git.sealed-content-observation.v2\0");
    append_bytes(&mut buffer, repository_id.as_str().as_bytes());
    for count in [
        observed_trees,
        observed_entries,
        coverage.regular_file_entries,
        coverage.executable_file_entries,
        coverage.symlink_entries,
        coverage.gitlink_entries,
        coverage.sealed_bodies,
        coverage.empty_bodies,
        coverage.opaque_bodies,
        coverage.non_utf8_paths,
    ] {
        buffer.extend_from_slice(&(count as u64).to_le_bytes());
    }
    buffer.extend_from_slice(&coverage.sealed_body_bytes.to_le_bytes());
    buffer.extend_from_slice(&(tree_content_digests.len() as u64).to_le_bytes());
    for tree_digest in tree_content_digests {
        buffer.extend_from_slice(tree_digest.as_bytes());
    }
    buffer.extend_from_slice(&(exclusions.len() as u64).to_le_bytes());
    for exclusion in exclusions {
        append_bytes(&mut buffer, exclusion.path.as_bytes());
        match &exclusion.reason {
            ContentExclusionReason::ForeignGitlinkTarget { target } => {
                buffer.push(1);
                append_bytes(&mut buffer, target.to_string().as_bytes());
            }
        }
    }
    digest(&buffer)
}

fn append_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buffer.extend_from_slice(bytes);
}

// Every case here builds a real Git repository carrying symlinks, executable
// bits, and non-UTF-8 paths, which is unix-only. Gating the module rather than
// each item keeps its helpers from becoming dead code on Windows, which CI
// rejects under `-D warnings`.
#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::path::Path;

    use pretty_assertions::assert_eq;
    use tempfile::{tempdir, TempDir};

    use super::*;
    use crate::admission_history::admit_semantic_git_import;
    use crate::lossless::capture_lossless_git_repository;
    use crate::semantic_import::plan_semantic_git_import;
    use crate::test_support::fixture_git;

    /// A content source backed by a real store with selected bodies withheld,
    /// so the fail-closed path is exercised against the production seal rather
    /// than a hand-rolled stub.
    struct WithholdingSource<'a> {
        inner: &'a BlobStore,
        withheld: Vec<Hash256>,
        corrupted: Vec<Hash256>,
    }

    impl SealedContentSource for WithholdingSource<'_> {
        fn load_sealed_content(&self, digest: Hash256) -> std::result::Result<Vec<u8>, String> {
            if self.withheld.contains(&digest) {
                return Err("blob not found".to_string());
            }
            if self.corrupted.contains(&digest) {
                return Ok(b"content that is not what the tree recorded".to_vec());
            }
            self.inner.load_sealed_content(digest)
        }
    }

    /// An explicit closure, so a test can seal a deliberately altered one
    /// through the production observation rather than asserting against a
    /// hand-computed fingerprint.
    struct ObservedTrees {
        repository_id: RepositoryId,
        content: AdmittedContentSummary,
        seed: ResolvedTree,
    }

    impl ObservedTrees {
        fn from_closure(closure: &impl AdmittedContentClosure) -> Self {
            Self {
                repository_id: closure.closure_repository_id().clone(),
                content: closure.admitted_content().into_owned(),
                seed: closure.admitted_seed_tree().clone(),
            }
        }

        /// Exchange the bodies of two same-shape entries in the last admitted
        /// tree, the workspace seed's, leaving every count and the byte total
        /// untouched.
        fn with_exchanged_head_bodies(&self, left: &[u8], right: &[u8]) -> Self {
            let left = RepoPath::from_bytes(left.to_vec()).unwrap();
            let right = RepoPath::from_bytes(right.to_vec()).unwrap();
            let mut head = self.seed.clone();
            let left_entry = head
                .artifact_at_path(&left)
                .expect("left path exists")
                .entry;
            let right_entry = head
                .artifact_at_path(&right)
                .expect("right path exists")
                .entry;
            assert_ne!(
                left_entry, right_entry,
                "exchanging equal entries is not a divergence"
            );
            let exchanged = head
                .clone()
                .into_artifacts()
                .map(|mut artifact| {
                    if artifact.path == left {
                        artifact.entry = right_entry;
                    } else if artifact.path == right {
                        artifact.entry = left_entry;
                    }
                    artifact
                })
                .collect::<Vec<_>>();
            head = ResolvedTree::from_artifacts(exchanged).unwrap();
            Self {
                repository_id: self.repository_id.clone(),
                content: self.content.clone(),
                seed: head,
            }
        }
    }

    impl AdmittedContentClosure for ObservedTrees {
        fn closure_repository_id(&self) -> &RepositoryId {
            &self.repository_id
        }

        fn admitted_content(&self) -> Cow<'_, AdmittedContentSummary> {
            Cow::Borrowed(&self.content)
        }

        fn admitted_seed_tree(&self) -> &ResolvedTree {
            &self.seed
        }
    }

    #[cfg(unix)]
    struct ExactFixture {
        _root: TempDir,
        blob_store: BlobStore,
        plan: SemanticGitImportPlan,
        binary_body: Hash256,
        symlink_body: Hash256,
        executable_body: Hash256,
        empty_body: Hash256,
    }

    #[cfg(unix)]
    impl ExactFixture {
        /// A repository carrying every shape the seal must cover: text, an
        /// opaque binary, an empty file, an executable bit, a symlink, a
        /// gitlink, and a path this host cannot name as UTF-8.
        fn all_shapes() -> Self {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let root = tempdir().unwrap();
            let repo = root.path().join("source");
            fs::create_dir(&repo).unwrap();
            git_ok(&repo, ["init", "--initial-branch=main"]);
            configure_git(&repo);

            write(&repo, "src/lib.rs", b"pub fn value() -> u8 { 7 }\n");
            write(&repo, "assets/raw.bin", &[0, 255, 1, 128, b'\n', 0, 42]);
            write(&repo, "empty.txt", b"");
            write(&repo, "scripts/tool.sh", b"#!/bin/sh\nprintf 'kin\\n'\n");
            let executable = repo.join("scripts/tool.sh");
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            symlink("src/lib.rs", repo.join("source-link")).unwrap();
            git_ok(&repo, ["add", "--all"]);

            let non_utf8 = git_stdin_text(&repo, ["hash-object", "-w", "--stdin"], &[0xde, 0xad]);
            let mut index_entry = format!("100644 {non_utf8}\t").into_bytes();
            index_entry.extend_from_slice(b"odd-\xff.bin\0");
            git_stdin_ok(&repo, ["update-index", "-z", "--index-info"], &index_entry);
            git_ok(
                &repo,
                [
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    "160000,4242424242424242424242424242424242424242,vendor/sub",
                ],
            );
            git_ok(&repo, ["commit", "-m", "exact tree with every shape"]);

            write(&repo, "src/lib.rs", b"pub fn value() -> u8 { 8 }\n");
            git_ok(&repo, ["add", "src/lib.rs"]);
            git_ok(&repo, ["commit", "-m", "second revision"]);

            let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
            let snapshot = capture_lossless_git_repository(
                &repo,
                RepositoryId::new("sealed-observation").unwrap(),
                &blob_store,
            )
            .unwrap();
            let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();

            let binary_body = body_at(&plan, b"assets/raw.bin");
            let symlink_body = body_at(&plan, b"source-link");
            let executable_body = body_at(&plan, b"scripts/tool.sh");
            let empty_body = body_at(&plan, b"empty.txt");
            Self {
                _root: root,
                blob_store,
                plan,
                binary_body,
                symlink_body,
                executable_body,
                empty_body,
            }
        }
    }

    #[cfg(unix)]
    fn body_at(plan: &SemanticGitImportPlan, path: &[u8]) -> Hash256 {
        let path = RepoPath::from_bytes(path.to_vec()).unwrap();
        plan.workspace_seed
            .base_tree
            .artifact_at_path(&path)
            .unwrap_or_else(|| {
                panic!(
                    "fixture is missing {}",
                    String::from_utf8_lossy(path.as_bytes())
                )
            })
            .entry
            .blob_identity()
            .expect("fixture entry carries content")
    }

    #[cfg(unix)]
    #[test]
    fn seals_every_content_shape_and_declares_only_foreign_gitlinks() {
        let fixture = ExactFixture::all_shapes();
        let observation = seal_all_content_observation(&fixture.plan, &fixture.blob_store).unwrap();

        // Two commits plus the workspace seed tree, each carrying the same
        // seven paths: four plain files, one executable, one symlink, one
        // gitlink.
        assert_eq!(observation.observed_trees, 3);
        assert_eq!(observation.observed_entries, 21);
        assert_eq!(observation.coverage.regular_file_entries, 12);
        assert_eq!(observation.coverage.executable_file_entries, 3);
        assert_eq!(observation.coverage.symlink_entries, 3);
        assert_eq!(observation.coverage.gitlink_entries, 3);
        assert_eq!(observation.coverage.non_utf8_paths, 1);

        // Seven distinct bodies: two revisions of the source file, the opaque
        // binary, the empty file, the executable, the symlink target, and the
        // body behind the non-UTF-8 path. All are sealed, none is skipped.
        assert_eq!(observation.coverage.sealed_bodies, 7);
        assert_eq!(observation.coverage.sealed_body_bytes, 98);
        assert_eq!(observation.coverage.opaque_bodies, 1);
        assert_eq!(observation.coverage.empty_bodies, 1);
        for body in [
            fixture.binary_body,
            fixture.symlink_body,
            fixture.executable_body,
            fixture.empty_body,
        ] {
            fixture.blob_store.read(&body).unwrap();
        }

        // The only declared exclusion is the foreign submodule pointer, and no
        // entity is invented for it.
        assert_eq!(observation.exclusions.len(), 1);
        let exclusion = &observation.exclusions[0];
        assert_eq!(exclusion.path.as_bytes(), b"vendor/sub");
        assert!(matches!(
            exclusion.reason,
            ContentExclusionReason::ForeignGitlinkTarget { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn admitted_and_unadmitted_closures_seal_to_the_same_fingerprint() {
        let fixture = ExactFixture::all_shapes();
        let admitted = admit_semantic_git_import(&fixture.plan, &fixture.blob_store).unwrap();

        let from_plan = seal_all_content_observation(&fixture.plan, &fixture.blob_store).unwrap();
        let from_admitted = seal_all_content_observation(&admitted, &fixture.blob_store).unwrap();
        assert_eq!(from_admitted, from_plan);
    }

    #[cfg(unix)]
    #[test]
    fn fails_closed_when_an_opaque_body_is_absent_from_graph_storage() {
        let fixture = ExactFixture::all_shapes();
        let source = WithholdingSource {
            inner: &fixture.blob_store,
            withheld: vec![fixture.binary_body],
            corrupted: Vec::new(),
        };

        let error = seal_all_content_observation(&fixture.plan, &source).unwrap_err();
        let described = error.to_string();
        let GitError::UnsealedContent {
            total_gaps,
            reported,
        } = error
        else {
            panic!("absent content must fail as an unsealed-content gap, got {described}");
        };
        // One body is withheld, and the three admitted trees that reference it
        // are one gap, not three. A count that grew per occurrence would make a
        // complete report read as a truncated one.
        assert_eq!(total_gaps, 1);
        assert_eq!(reported.len(), 1);
        assert!(
            !described.contains("further gap"),
            "a report that lists every gap must not read as truncated: {described}"
        );
        let gap = reported
            .iter()
            .find(|gap| gap.path == b"assets/raw.bin")
            .expect("the withheld binary is reported by path");
        assert_eq!(gap.expected, fixture.binary_body.to_string());
    }

    #[cfg(unix)]
    #[test]
    fn fails_closed_when_a_symlink_target_body_does_not_match_its_identity() {
        let fixture = ExactFixture::all_shapes();
        let source = WithholdingSource {
            inner: &fixture.blob_store,
            withheld: Vec::new(),
            corrupted: vec![fixture.symlink_body],
        };

        let error = seal_all_content_observation(&fixture.plan, &source).unwrap_err();
        let GitError::UnsealedContent { reported, .. } = error else {
            panic!("a body/identity mismatch must fail closed, got {error:?}");
        };
        let gap = reported
            .iter()
            .find(|gap| gap.path == b"source-link")
            .expect("the corrupted symlink target is reported by path");
        assert!(
            gap.detail.contains("hashes to"),
            "the gap names the mismatch: {}",
            gap.detail
        );
    }

    #[cfg(unix)]
    #[test]
    fn seal_is_deterministic_and_binds_the_observed_counts() {
        let fixture = ExactFixture::all_shapes();
        let first = seal_all_content_observation(&fixture.plan, &fixture.blob_store).unwrap();
        let second = seal_all_content_observation(&fixture.plan, &fixture.blob_store).unwrap();
        assert_eq!(second.fingerprint, first.fingerprint);

        // Coverage drift changes the identity with the observed content held
        // fixed, so the counts are bound as well as the content.
        let observed_content = [digest(b"one admitted tree")];
        let baseline = fingerprint_observation(
            &first.repository_id,
            first.observed_trees,
            first.observed_entries,
            &first.coverage,
            &first.exclusions,
            &observed_content,
        );
        let mut drifted = first.coverage;
        drifted.symlink_entries += 1;
        let refingerprinted = fingerprint_observation(
            &first.repository_id,
            first.observed_trees,
            first.observed_entries,
            &drifted,
            &first.exclusions,
            &observed_content,
        );
        assert_ne!(refingerprinted, baseline);
    }

    #[cfg(unix)]
    #[test]
    fn seal_separates_identical_counts_that_describe_different_content() {
        let fixture = ExactFixture::all_shapes();
        let observed = ObservedTrees::from_closure(&fixture.plan);
        let diverged = observed.with_exchanged_head_bodies(b"src/lib.rs", b"assets/raw.bin");

        let from_observed = seal_all_content_observation(&observed, &fixture.blob_store).unwrap();
        let from_diverged = seal_all_content_observation(&diverged, &fixture.blob_store).unwrap();

        // Exchanging two bodies between two paths of the same shape seals the
        // same distinct bodies, the same byte total, and every same count. Only
        // a fingerprint that binds which body sits at which path can tell the
        // two observations apart, so the seal is a content statement rather
        // than a tally.
        assert_eq!(from_diverged.observed_trees, from_observed.observed_trees);
        assert_eq!(
            from_diverged.observed_entries,
            from_observed.observed_entries
        );
        assert_eq!(from_diverged.coverage, from_observed.coverage);
        assert_eq!(from_diverged.exclusions, from_observed.exclusions);
        assert_ne!(from_diverged.fingerprint, from_observed.fingerprint);

        // The unaltered explicit closure still fingerprints exactly like the
        // plan it was derived from.
        let from_plan = seal_all_content_observation(&fixture.plan, &fixture.blob_store).unwrap();
        assert_eq!(from_observed.fingerprint, from_plan.fingerprint);
    }

    fn write(repo: &Path, relative: &str, body: &[u8]) {
        let path = repo.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn configure_git(repo: &Path) {
        git_ok(repo, ["config", "user.name", "Kin Test"]);
        git_ok(repo, ["config", "user.email", "test@kin.invalid"]);
        git_ok(repo, ["config", "commit.gpgsign", "false"]);
    }

    fn git_ok<const N: usize>(repo: &Path, args: [&str; N]) {
        let output = git(repo, args, None);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_stdin_ok<const N: usize>(repo: &Path, args: [&str; N], stdin: &[u8]) {
        let output = git(repo, args, Some(stdin));
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_stdin_text<const N: usize>(repo: &Path, args: [&str; N], stdin: &[u8]) -> String {
        let output = git(repo, args, Some(stdin));
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn git<const N: usize>(
        repo: &Path,
        args: [&str; N],
        stdin: Option<&[u8]>,
    ) -> std::process::Output {
        let mut command = fixture_git();
        command.current_dir(repo).args(args);
        if let Some(input) = stdin {
            command.output_with_input(input).unwrap()
        } else {
            command.output().unwrap()
        }
    }
}
