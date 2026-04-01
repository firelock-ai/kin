// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("contract not found: {0}")]
    NotFound(String),

    #[error("schema parse error: {0}")]
    SchemaParse(String),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("linking error: {0}")]
    Linking(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ContractError>;
