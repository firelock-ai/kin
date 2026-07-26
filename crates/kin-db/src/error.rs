// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// Errors returned by KinDB operations.
#[derive(Debug, Error)]
pub enum KinDbError {
    #[error(transparent)]
    Model(#[from] kin_model::ModelError),

    #[error("entity not found: {0}")]
    NotFound(String),

    #[error("duplicate entity: {0}")]
    DuplicateEntity(String),

    #[error("semantic change id already exists with a different payload: {0}")]
    DuplicateChange(String),

    #[error("storage error: {0}")]
    StorageError(String),

    /// A snapshot write may have installed its exact candidate, but the
    /// backend could not prove the commit outcome to the caller.
    ///
    /// Callers must retain and reconcile that same candidate. Rebuilding a
    /// successor can change timestamps or other serialized identity and can
    /// therefore neither confirm nor safely supersede the uncertain write.
    #[error("snapshot persistence outcome is indeterminate: {0}")]
    SnapshotPersistenceIndeterminate(String),

    #[error(
        "immutable source blob is {actual_bytes} bytes, above the caller-supplied {max_bytes}-byte read limit"
    )]
    SourceBlobReadLimitExceeded { actual_bytes: u64, max_bytes: u64 },

    #[error("incompatible snapshot schema: on-disk snapshot format version {found} {direction} the range this binary supports (versions {min} through {max}); {remediation}")]
    IncompatibleSnapshotVersion {
        found: u32,
        min: u32,
        max: u32,
        direction: &'static str,
        remediation: &'static str,
    },

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("index error: {0}")]
    IndexError(String),

    #[error("lock error: {0}")]
    LockError(String),

    #[error("concurrent access error: {0}")]
    ConcurrentAccessError(String),

    #[error("slice conversion error: {0}")]
    SliceConversionError(String),
}

impl KinDbError {
    /// Error for a snapshot whose format predates exact universal-tree truth.
    pub fn snapshot_schema_too_old(found: u32, min: u32, max: u32) -> Self {
        KinDbError::IncompatibleSnapshotVersion {
            found,
            min,
            max,
            direction: "is older than",
            remediation: "reinitialize this pre-release repository with the current Kin; exact file modes cannot be recovered from this snapshot",
        }
    }

    /// Error for a snapshot whose format version is newer than this binary
    /// understands. Names the version gap and the upgrade remediation.
    pub fn snapshot_schema_too_new(found: u32, min: u32, max: u32) -> Self {
        KinDbError::IncompatibleSnapshotVersion {
            found,
            min,
            max,
            direction: "is newer than",
            remediation: "this graph was written by a newer Kin; upgrade Kin to a build that supports this snapshot",
        }
    }
}

pub type Result<T> = std::result::Result<T, KinDbError>;

#[cfg(test)]
mod tests {
    use super::KinDbError;

    #[test]
    fn model_history_errors_preserve_their_typed_cause() {
        let error = KinDbError::from(kin_model::ModelError::ChangeNotFound(
            "missing-parent".to_string(),
        ));

        assert!(matches!(
            error,
            KinDbError::Model(kin_model::ModelError::ChangeNotFound(id))
                if id == "missing-parent"
        ));
    }

    #[test]
    fn source_blob_read_limit_error_has_stable_fields_and_display() {
        let error = KinDbError::SourceBlobReadLimitExceeded {
            actual_bytes: 300,
            max_bytes: 256,
        };

        assert_eq!(
            error.to_string(),
            "immutable source blob is 300 bytes, above the caller-supplied 256-byte read limit"
        );
        assert!(matches!(
            error,
            KinDbError::SourceBlobReadLimitExceeded {
                actual_bytes: 300,
                max_bytes: 256
            }
        ));
    }
}
