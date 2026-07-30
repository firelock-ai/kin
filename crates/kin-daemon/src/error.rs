// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;
use thiserror::Error;

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
