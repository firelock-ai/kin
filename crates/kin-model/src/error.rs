// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("entity not found: {0}")]
    EntityNotFound(String),

    #[error("relation not found: {0}")]
    RelationNotFound(String),

    #[error("branch not found: {0}")]
    BranchNotFound(String),

    #[error("change not found: {0}")]
    ChangeNotFound(String),

    #[error("invalid hash: {0}")]
    InvalidHash(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("invalid operation: {0}")]
    InvalidOperation(String),
}

pub type Result<T> = std::result::Result<T, ModelError>;
