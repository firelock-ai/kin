// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// One other Git worktree registered against the source object database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredGitWorktreeFact {
    pub kind: RegisteredGitWorktreeKind,
    pub id: Option<Vec<u8>>,
    pub path: std::path::PathBuf,
    /// Where that worktree keeps its own HEAD, index, and administrative
    /// state. Everything private to a worktree lives here rather than in the
    /// shared object database, which is the whole reason a sibling has to be
    /// classified separately from the source.
    pub git_dir: std::path::PathBuf,
    pub locked: bool,
}

/// One other registered worktree this migration cannot tolerate, and why.
///
/// A sibling worktree is ordinary. What makes one untolerable is state the
/// capture cannot see: refs the shared store does not publish, or an operation
/// still running against the object database. `reason` names that state and
/// `remedy` is the one action that clears it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntolerableGitWorktree {
    pub worktree: RegisteredGitWorktreeFact,
    pub reason: String,
    pub remedy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredGitWorktreeKind {
    Main,
    Linked,
}

/// A local hook surface intentionally not imported or executed by Kin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalGitHookFact {
    pub name: Vec<u8>,
    /// Where the hook actually lives. Under a `core.hooksPath` override this is
    /// not under `.git/hooks`, which is why the name alone cannot locate it.
    pub path: std::path::PathBuf,
    pub kind: LocalGitHookKind,
    pub executable: LocalGitHookExecutability,
    pub byte_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalGitHookKind {
    File,
    Symlink,
    Directory,
    Other,
}

/// Whether the host filesystem reports one local hook as executable.
///
/// A platform whose filesystem carries no executable bit is reported as such
/// rather than as a non-executable hook: the two are different observations,
/// and collapsing them would claim a mode nothing recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalGitHookExecutability {
    Executable,
    NotExecutable,
    /// The host filesystem records no executable bit for this entry.
    Unrecorded,
}

/// Presence-only description of a configured external checkout filter.
///
/// Command values are deliberately omitted so credentials or executable
/// configuration cannot leak into Kin authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCheckoutFilterFact {
    pub name: Vec<u8>,
    pub clean_present: bool,
    pub smudge_present: bool,
    pub process_present: bool,
    pub required_present: bool,
}

/// One admitted entry whose content the graph cannot answer for.
///
/// Paths and identities are carried as plain bytes and text so a gap report
/// survives into an error without depending on repository model types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsealedContentGap {
    pub path: Vec<u8>,
    /// Content identity the admitted tree requires.
    pub expected: String,
    /// Why the body could not be sealed: absent, unreadable, or not matching
    /// the identity the tree recorded.
    pub detail: String,
}

/// One reason this Git source cannot be admitted, with the way out.
///
/// `subject` names the exact path, hook, or configuration key that blocks, and
/// `remedy` is the single action that clears it. A blocker that cannot say both
/// is a category rather than a finding and does not belong here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitAdmissionBlocker {
    pub subject: String,
    pub remedy: String,
}

impl GitAdmissionBlocker {
    pub fn new(subject: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            remedy: remedy.into(),
        }
    }
}

/// Render every blocker and note as its own line.
///
/// The count leads so a reader knows how much is coming before reading any of
/// it, and notes trail the list because they explain what was *not* counted.
fn describe_admission_blockers(blockers: &[GitAdmissionBlocker], notes: &[String]) -> String {
    let mut described = format!(
        "this Git repository has {} admission blocker(s):",
        blockers.len()
    );
    for blocker in blockers {
        described.push_str(&format!("\n  - {}; {}", blocker.subject, blocker.remedy));
    }
    for note in notes {
        described.push_str(&format!("\n  note: {note}"));
    }
    described
}

/// Render a gap report so the failure names the paths an operator must fix.
///
/// The count and the sample both count distinct unsealed bodies, so the exact
/// count is reported, a truncated sample says so, and a sample that lists every
/// gap it found never reads as truncated.
fn describe_unsealed_gaps(total_gaps: usize, reported: &[UnsealedContentGap]) -> String {
    let mut described = reported
        .iter()
        .map(|gap| {
            format!(
                "{} (expects {}: {})",
                String::from_utf8_lossy(&gap.path),
                gap.expected,
                gap.detail
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if total_gaps > reported.len() {
        described.push_str(&format!(
            "; and {} further gap(s) not listed",
            total_gaps - reported.len()
        ));
    }
    described
}

/// Render every untolerable sibling worktree with its path, reason, and remedy.
fn describe_untolerable_worktrees(worktrees: &[UntolerableGitWorktree]) -> String {
    worktrees
        .iter()
        .map(|entry| {
            format!(
                "the {} worktree {} {} ({})",
                match entry.worktree.kind {
                    RegisteredGitWorktreeKind::Main => "main",
                    RegisteredGitWorktreeKind::Linked => "linked",
                },
                entry.worktree.path.display(),
                entry.reason,
                entry.remedy
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Errors from the kin-git adapter.
#[derive(Debug, Error)]
pub enum GitError {
    #[error("git repository not found at: {0}")]
    RepoNotFound(String),

    #[error("not a git repository: {0}")]
    NotAGitRepo(String),

    #[error("git error: {0}")]
    Git(String),

    #[error("commit not found: {0}")]
    CommitNotFound(String),

    #[error("branch not found: {0}")]
    BranchNotFound(String),

    #[error("no commits in repository")]
    EmptyRepository,

    /// The refusal is correct: Kin's ingest contract is lossless capture of
    /// everything reachable, and a shallow clone is genuinely un-capturable
    /// under it. What the message has to add is the way out, because
    /// `actions/checkout` clones at depth 1 by default and this is therefore the
    /// first thing Kin says to anyone trying it inside CI.
    #[error("shallow Git repositories cannot be imported losslessly; run 'git fetch --unshallow' first (in CI, actions/checkout needs fetch-depth: 0)")]
    ShallowRepository,

    #[error("Git object {oid} is missing while traversing {context}")]
    MissingObject { oid: String, context: String },

    #[error("Git object {oid} is corrupt: {reason}")]
    CorruptObject { oid: String, reason: String },

    #[error("lossless Git snapshot is invalid: {0}")]
    InvalidSnapshot(String),

    #[error("Git migration preflight failed: {0}")]
    MigrationPreflight(String),

    /// Every source-state reason admission would refuse, reported together
    /// before any history is derived.
    ///
    /// One blocker at a time, arriving after minutes of derivation, turns a
    /// five-minute cleanup into an afternoon of guessing. This variant carries
    /// the whole list so a reader fixes the repository once.
    #[error("{}", describe_admission_blockers(blockers, notes))]
    AdmissionBlocked {
        blockers: Vec<GitAdmissionBlocker>,
        /// Context that changes how the list reads, such as a `core.hooksPath`
        /// that makes `.git/hooks` inert, or Kin's own legacy hook links.
        notes: Vec<String>,
    },

    #[error(
        "Git migration source shares its object database with {count} worktree(s) holding state this capture cannot prove: {}",
        describe_untolerable_worktrees(worktrees)
    )]
    AdditionalWorktrees {
        count: usize,
        worktrees: Vec<UntolerableGitWorktree>,
    },

    #[error(
        "Git migration source has local compatibility blockers ({hook_count} hook(s), custom hooks path: {custom_hooks_path}, {filter_count} checkout filter(s))"
    )]
    LocalCompatibilityBlockers {
        hook_count: usize,
        custom_hooks_path: bool,
        filter_count: usize,
        hooks: Vec<LocalGitHookFact>,
        filters: Vec<GitCheckoutFilterFact>,
    },

    #[error(
        "sealed all-content observation failed: {total_gaps} admitted bod(ies) are not byte-exact in graph-owned storage, so this repository cannot answer for its own content without reading the filesystem: {}",
        describe_unsealed_gaps(*total_gaps, reported)
    )]
    UnsealedContent {
        /// Distinct unsealed bodies, counted once each however many admitted
        /// entries reference them.
        total_gaps: usize,
        /// A bounded sample of the gaps, one entry per distinct unsealed body.
        /// `total_gaps` is always the exact count.
        reported: Vec<UnsealedContentGap>,
    },

    #[error("Git object format {0} is not supported for exact rehydration")]
    UnsupportedObjectFormat(String),

    #[error("Git rehydration destination already exists: {0}")]
    DestinationExists(String),

    #[error("io error: {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("blob error: {0}")]
    Blob(#[from] kin_blobs::BlobError),

    #[error("model error: {0}")]
    Model(#[from] kin_model::ModelError),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("{0}")]
    Other(String),
}

impl GitError {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, GitError>;
