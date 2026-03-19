// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// Errors from the context pack builder.
#[derive(Debug, Error)]
pub enum ContextError {
    #[error("entity not found: {0}")]
    EntityNotFound(String),

    #[error("token budget exceeded: {actual} > {budget}")]
    BudgetExceeded { actual: usize, budget: usize },

    #[error("graph error: {0}")]
    Graph(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ContextError>;
