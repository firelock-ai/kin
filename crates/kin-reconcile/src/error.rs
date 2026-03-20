// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReconcileError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Index error: {0}")]
    Index(String),

    #[error("Graph error: {0}")]
    Graph(String),

    #[error("Projection error: {0}")]
    Projection(String),

    #[error("Blob error: {0}")]
    Blob(String),

    #[error("IO error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("Body extraction failed for entity {entity_id}: {reason}")]
    BodyExtractionFailed {
        entity_id: kin_model::EntityId,
        reason: String,
    },

    #[error("Broken AST rejected by policy for file {file_id}")]
    BrokenAstRejected {
        file_id: kin_model::FilePathId,
        error_ranges: Vec<(usize, usize)>,
    },

    #[error("Validation failed for entity {entity_id}: {reason}")]
    ValidationFailed {
        entity_id: kin_model::EntityId,
        reason: String,
    },

    #[error("Collision blocked: {reason}")]
    CollisionBlocked {
        reason: String,
        blocking_intents: Vec<kin_model::IntentSummary>,
    },

    #[error("Traffic checker error: {0}")]
    TrafficCheck(String),

    #[error("Modify-delete conflict on entity {entity_id}: one side modified, the other deleted")]
    ModifyDeleteConflict {
        entity_id: kin_model::EntityId,
        /// The modification delta (the entity state from the side that modified).
        modification: Box<kin_model::Entity>,
        /// True if the local side deleted and remote modified; false if local modified and remote deleted.
        local_deleted: bool,
    },
}

impl ReconcileError {
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl From<kin_parser::ParseError> for ReconcileError {
    fn from(e: kin_parser::ParseError) -> Self {
        Self::Parse(e.to_string())
    }
}

impl From<kin_index::IndexError> for ReconcileError {
    fn from(e: kin_index::IndexError) -> Self {
        Self::Index(e.to_string())
    }
}

impl From<kin_projection::ProjectionError> for ReconcileError {
    fn from(e: kin_projection::ProjectionError) -> Self {
        Self::Projection(e.to_string())
    }
}

impl From<kin_blobs::BlobError> for ReconcileError {
    fn from(e: kin_blobs::BlobError) -> Self {
        Self::Blob(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ReconcileError>;
