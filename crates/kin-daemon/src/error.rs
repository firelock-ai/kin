// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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

    #[error("{0}")]
    IncompatibleRepo(String),

    #[error("Already running")]
    AlreadyRunning,

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
