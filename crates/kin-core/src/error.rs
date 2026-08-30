// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// Which kind of projection conflict a refusal is.
///
/// The message alone cannot carry this. Two of these refusals are answered very
/// differently by a caller and were distinguishable only by their wording, and
/// a predicate on wording is a check a copy edit breaks in silence.
///
/// `Other` exists so every site with no opinion keeps its behaviour rather than
/// being made to claim one, and so a new site cannot pick a kind by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionConflictKind {
    /// A path the repository TRACKS whose working-copy content has moved away
    /// from the projection. The graph has not been told yet, and an admission
    /// pass resolves it, which is why this one is worth naming.
    TrackedDrift,
    /// A path the repository does NOT track standing where a member must go. No
    /// admission makes this carry; the caller has to move or remove the file.
    UntrackedBlocks,
    /// Every other projection conflict, which is most of them.
    Other,
}

/// A projection conflict, with its kind beside the sentence.
///
/// Displays as the message alone, so every existing rendering of this error is
/// byte identical to what it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionConflictDetail {
    pub kind: ProjectionConflictKind,
    pub message: String,
}

impl ProjectionConflictDetail {
    pub fn new(kind: ProjectionConflictKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ProjectionConflictDetail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// Every site that says nothing about the kind keeps saying nothing.
impl From<String> for ProjectionConflictDetail {
    fn from(message: String) -> Self {
        Self::new(ProjectionConflictKind::Other, message)
    }
}

/// Unified error type for `kin-core`.
#[derive(Debug, Error)]
pub enum KinError {
    #[error("IO error: {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("config error: {0}")]
    Config(String),

    #[error("toml parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("toml serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("already initialized: {0}")]
    AlreadyInitialized(String),

    #[error(
        "repository was published at {path}, but durability or final verification is uncertain: \
         {detail}. Do not reinitialize or delete it; reopen and verify the existing repository"
    )]
    RepositoryPublishedButUncertain { path: String, detail: String },

    #[error("repository authority conflict: {0}")]
    RepositoryConflict(String),

    #[error("repository projection conflict: {0}")]
    ProjectionConflict(ProjectionConflictDetail),

    /// The working projection will not open until a person acts on the file
    /// the message names.
    ///
    /// Neither a conflict nor an internal failure: the store is intact and the
    /// sentence carries the remedy. A daemon answers it as a refusal in words
    /// rather than as HTTP 500, because sending a reader to the daemon for a
    /// file they can see is how a stale eject journal cost a stranger the whole
    /// write path on 0.5.52 (FIR-2664).
    #[error("{0}")]
    ProjectionBlocked(String),

    #[error("repository authority commit outcome is indeterminate: {0}")]
    RepositoryCommitIndeterminate(String),

    #[error("not a kin repository: {0}")]
    NotARepository(String),

    #[error("model error: {0}")]
    Model(#[from] kin_model::ModelError),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("incompatible .kin/ version: found v{found}, this binary requires v{supported}")]
    IncompatibleVersion { found: u32, supported: u32 },

    /// The conversion was turned away at phase 1 because it forecasts needing
    /// more memory than this process can read as a ceiling.
    ///
    /// Carries no detail on purpose. The numbers, the ceiling and both remedies
    /// have already been written to stderr as their own lines, in the same
    /// register and through the same pipe-safe writer as the killed-conversion
    /// post-mortem, and repeating them inside an `anyhow` cause chain would
    /// print the whole paragraph a second time under a `Caused by:` heading.
    #[error(
        "not enough memory for this conversion; the lines above name the forecast, the ceiling \
         and what to do about it"
    )]
    ConversionBudgetExceeded,

    #[error("{0}")]
    Other(String),
}

impl KinError {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }

    /// A projection conflict whose kind this site does not claim.
    pub fn projection_conflict(message: impl Into<String>) -> Self {
        Self::ProjectionConflict(ProjectionConflictDetail::new(
            ProjectionConflictKind::Other,
            message,
        ))
    }

    /// A TRACKED path whose working-copy content moved away from the projection.
    pub fn tracked_projection_drift(message: impl Into<String>) -> Self {
        Self::ProjectionConflict(ProjectionConflictDetail::new(
            ProjectionConflictKind::TrackedDrift,
            message,
        ))
    }

    /// An UNTRACKED path standing where a member must go.
    pub fn untracked_path_blocks(message: impl Into<String>) -> Self {
        Self::ProjectionConflict(ProjectionConflictDetail::new(
            ProjectionConflictKind::UntrackedBlocks,
            message,
        ))
    }

    /// The kind of projection conflict this is, or `None` when it is not one.
    ///
    /// Read by a caller that answers two of these differently. Everything else
    /// keeps matching the variant and rendering the message, which is unchanged.
    pub fn projection_conflict_kind(&self) -> Option<ProjectionConflictKind> {
        match self {
            Self::ProjectionConflict(detail) => Some(detail.kind),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, KinError>;
