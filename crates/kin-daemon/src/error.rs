// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("Graph error")]
    Graph(#[source] kin_db::KinDbError),

    #[error("Blob error")]
    Blob(#[source] kin_blobs::BlobError),

    #[error("Index error")]
    Index(#[source] kin_index::IndexError),

    #[error("Reconcile error")]
    Reconcile(#[source] kin_reconcile::ReconcileError),

    #[error("Core error")]
    Core(#[source] kin_core::KinError),

    #[error("Not initialized: no .kin/ directory found")]
    NotInitialized,

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

impl From<kin_core::KinError> for DaemonError {
    fn from(e: kin_core::KinError) -> Self {
        Self::Core(e)
    }
}

pub type Result<T> = std::result::Result<T, DaemonError>;
