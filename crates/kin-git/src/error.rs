// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// One other Git worktree registered against the source object database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredGitWorktreeFact {
    pub kind: RegisteredGitWorktreeKind,
    pub id: Option<Vec<u8>>,
    pub path: std::path::PathBuf,
    pub locked: bool,
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
    pub kind: LocalGitHookKind,
    pub executable: bool,
    pub byte_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalGitHookKind {
    File,
    Symlink,
    Directory,
    Other,
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

    #[error("shallow Git repositories cannot be imported losslessly")]
    ShallowRepository,

    #[error("Git object {oid} is missing while traversing {context}")]
    MissingObject { oid: String, context: String },

    #[error("Git object {oid} is corrupt: {reason}")]
    CorruptObject { oid: String, reason: String },

    #[error("lossless Git snapshot is invalid: {0}")]
    InvalidSnapshot(String),

    #[error("Git migration preflight failed: {0}")]
    MigrationPreflight(String),

    #[error(
        "Git migration source has {count} other registered worktree(s); single-workspace import must account for each workspace"
    )]
    AdditionalWorktrees {
        count: usize,
        worktrees: Vec<RegisteredGitWorktreeFact>,
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
        "sealed all-content observation failed: {total_gaps} admitted entr(ies) have no byte-exact graph-owned body, so this repository cannot answer for its own content without reading the filesystem"
    )]
    UnsealedContent {
        total_gaps: usize,
        /// A bounded sample of the gaps. `total_gaps` is always the exact count.
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
