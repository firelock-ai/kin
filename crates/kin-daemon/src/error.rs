// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;
use thiserror::Error;

/// Render an error chain with its root cause as the headline.
///
/// `{error:#}` prints the outermost context first, which on the repository
/// routes is an internal step description such as "resolve exact graph for
/// branch main", leaving the reason the caller needs at the far end of the
/// line. Reversing the chain puts the cause where a reader looks for it and
/// keeps the steps that led there behind it.
pub fn cause_first(error: &anyhow::Error) -> String {
    let mut frames: Vec<String> = error.chain().map(ToString::to_string).collect();
    frames.reverse();
    frames.join(": ")
}

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("Graph error: {0}")]
    Graph(#[source] kin_db::KinDbError),

    #[error("Blob error: {0}")]
    Blob(#[source] kin_blobs::BlobError),

    #[error("Index error: {0}")]
    Index(#[source] kin_index::IndexError),

    #[error("Reconcile error: {0}")]
    Reconcile(#[source] kin_reconcile::ReconcileError),

    #[error("Projection error: {0}")]
    Projection(#[source] kin_projection::ProjectionError),

    #[error("Core error: {0}")]
    Core(#[source] kin_core::KinError),

    #[error("Not initialized: no .kin/ directory found")]
    NotInitialized,

    /// The storage backend answered completely and holds no such repository.
    ///
    /// Absence is a trustworthy answer, not a failure to answer: the backend
    /// was reachable, its authority read succeeded, and it reported nothing
    /// stored under this id. Every other storage arm is the opposite, whether
    /// an unreachable object store, expired credentials, or a corrupt delta
    /// chain, and callers must be able to route the two differently: a
    /// repository that is not there versus a daemon that cannot answer.
    ///
    /// This is typed rather than flattened into
    /// [`Graph`](Self::Graph)`(StorageError(..))` because recovering the
    /// distinction afterwards would mean matching on message text, and a
    /// classification inferred from a failure string is exactly what stops
    /// holding the first time the wording moves.
    #[error("repository '{0}' has no graph in storage")]
    RepoAbsentFromStorage(String),

    /// The requested repository lies outside the key space this daemon serves.
    ///
    /// This is the third answer alongside a repository that is there and one
    /// that is absent, and it is the only one decidable without touching
    /// storage: the configured key space already excludes the id, so no load is
    /// attempted and no backend state is consulted. Answering it as a storage
    /// outcome would describe a daemon that failed where nothing was ever
    /// asked of storage.
    ///
    /// Both identities travel with the refusal because either alone is
    /// unactionable. The requested id alone leaves the caller unable to tell a
    /// typo from a request sent to the wrong pod, and the served id alone does
    /// not say which request was refused. Carrying them here rather than
    /// rebuilding the sentence at each route also keeps every surface phrasing
    /// the same refusal identically.
    #[error(
        "this daemon serves repository {served} and does not serve {requested}; \
         GET /health advertises the repo_id this daemon accepts"
    )]
    RepoNotServed { served: String, requested: String },

    #[error("{0}")]
    IncompatibleRepo(String),

    #[error("Already running")]
    AlreadyRunning,

    #[error(
        "daemon authority protects {authority_root}, but daemon state belongs to {state_root}"
    )]
    AuthorityMismatch {
        authority_root: PathBuf,
        state_root: PathBuf,
    },

    /// A second daemon lost the per-repo singleton lock. Carries the actionable
    /// text naming the holder; a bare "already running" told the operator
    /// nothing about which process to wait for or stop.
    #[error("{0}")]
    RepoOwnedByAnotherDaemon(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<kin_db::KinDbError> for DaemonError {
    fn from(e: kin_db::KinDbError) -> Self {
        Self::Graph(e)
    }
}

impl From<kin_blobs::BlobError> for DaemonError {
    fn from(e: kin_blobs::BlobError) -> Self {
        Self::Blob(e)
    }
}

impl From<kin_index::IndexError> for DaemonError {
    fn from(e: kin_index::IndexError) -> Self {
        Self::Index(e)
    }
}

impl From<kin_reconcile::ReconcileError> for DaemonError {
    fn from(e: kin_reconcile::ReconcileError) -> Self {
        Self::Reconcile(e)
    }
}

impl From<kin_projection::ProjectionError> for DaemonError {
    fn from(e: kin_projection::ProjectionError) -> Self {
        Self::Projection(e)
    }
}

impl From<kin_core::KinError> for DaemonError {
    fn from(e: kin_core::KinError) -> Self {
        Self::Core(e)
    }
}

impl From<kin_model::ModelError> for DaemonError {
    fn from(error: kin_model::ModelError) -> Self {
        Self::Core(kin_core::KinError::Model(error))
    }
}

pub type Result<T> = std::result::Result<T, DaemonError>;

#[cfg(test)]
mod tests {
    use super::cause_first;
    use anyhow::Context;

    #[test]
    fn the_root_cause_leads_and_the_steps_that_reached_it_follow() {
        let error = anyhow::anyhow!("branch main has no graph snapshot")
            .context("resolve exact graph for branch main")
            .context("prepare merge replay validation");
        assert_eq!(
            cause_first(&error),
            "branch main has no graph snapshot: resolve exact graph for branch main: prepare \
             merge replay validation"
        );
        assert_ne!(
            cause_first(&error),
            format!("{error:#}"),
            "leading with the outermost step is the rendering being replaced"
        );
    }

    /// Classification by substring survives the reordering: the repository
    /// routes read their own refusal text to pick a status code, and a chain
    /// rendered in either direction contains the same frames.
    #[test]
    fn an_uncontextualized_error_renders_exactly_as_itself() {
        let error = anyhow::anyhow!("rename target is not a simple source identifier");
        assert_eq!(
            cause_first(&error),
            "rename target is not a simple source identifier"
        );
    }
}
