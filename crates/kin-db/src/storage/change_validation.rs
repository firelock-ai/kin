// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::error::KinDbError;
use crate::types::{SemanticChange, SemanticChangeId};

/// Validate one immutable semantic change before it crosses an authoritative
/// storage boundary.
pub(crate) fn validate_semantic_change(change: &SemanticChange) -> Result<(), KinDbError> {
    kin_model::validate_semantic_change_id(change)?;
    Ok(())
}

/// Validate both the collection key and the full-payload identity of one
/// semantic change.
pub(crate) fn validate_semantic_change_entry(
    key: &SemanticChangeId,
    change: &SemanticChange,
    boundary: &str,
) -> Result<(), KinDbError> {
    if key != &change.id {
        return Err(KinDbError::StorageError(format!(
            "{boundary} semantic change map key {key} does not match declared id {}",
            change.id
        )));
    }
    validate_semantic_change(change)
}

/// Validate every keyed semantic change in an authoritative collection.
pub(crate) fn validate_semantic_change_entries<'a>(
    entries: impl IntoIterator<Item = (&'a SemanticChangeId, &'a SemanticChange)>,
    boundary: &str,
) -> Result<(), KinDbError> {
    for (key, change) in entries {
        validate_semantic_change_entry(key, change, boundary)?;
    }
    Ok(())
}
