// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Crash-recoverable cleanup primitives for local delta journals.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::KinDbError;
use crate::storage::backend::{Generation, GENERATION_INIT};

const QUARANTINE_PREFIX: &str = ".kin-journal-cleanup-";

#[derive(Debug)]
pub(super) struct QuarantinedDelta {
    pub(super) generation: Generation,
    pub(super) sha256: String,
    pub(super) path: PathBuf,
    pub(super) bytes: Vec<u8>,
}

pub(super) fn quarantine_delta_path(
    canonical_path: &Path,
    generation: Generation,
    sha256: &str,
) -> PathBuf {
    canonical_path.with_file_name(format!(
        "{QUARANTINE_PREFIX}{generation:020}-{sha256}-{}.kndd",
        uuid::Uuid::new_v4()
    ))
}

pub(super) fn sync_parent_directory(path: &Path) -> Result<(), KinDbError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    #[cfg(not(unix))]
    {
        let _ = parent;
        Ok(())
    }
    #[cfg(unix)]
    {
        let directory = std::fs::File::open(parent).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open journal directory {} for fsync: {error}",
                parent.display()
            ))
        })?;
        directory.sync_all().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to fsync journal directory {}: {error}",
                parent.display()
            ))
        })
    }
}

pub(super) fn load_quarantined_deltas(
    delta_dir: &Path,
) -> Result<Vec<QuarantinedDelta>, KinDbError> {
    if !delta_dir.exists() {
        return Ok(Vec::new());
    }

    let mut quarantined = Vec::new();
    for entry in std::fs::read_dir(delta_dir).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read journal directory {}: {error}",
            delta_dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read journal entry in {}: {error}",
                delta_dir.display()
            ))
        })?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(QUARANTINE_PREFIX) {
            continue;
        }
        let encoded = name
            .strip_prefix(QUARANTINE_PREFIX)
            .and_then(|name| name.strip_suffix(".kndd"))
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let mut fields = encoded.splitn(3, '-');
        let generation_field = fields
            .next()
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let sha256 = fields
            .next()
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let nonce = fields
            .next()
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let generation = generation_field
            .parse::<Generation>()
            .map_err(|_| invalid_quarantine_name(&path))?;
        if generation == GENERATION_INIT
            || generation_field != format!("{generation:020}")
            || sha256.len() != 64
            || sha256.to_ascii_lowercase() != sha256
            || hex::decode(sha256).is_err()
            || uuid::Uuid::parse_str(nonce).is_err()
        {
            return Err(invalid_quarantine_name(&path));
        }
        let bytes = std::fs::read(&path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read quarantined delta {}: {error}",
                path.display()
            ))
        })?;
        let actual_sha256 = hex::encode(Sha256::digest(&bytes));
        if actual_sha256 != sha256 {
            return Err(KinDbError::StorageError(format!(
                "quarantined delta digest mismatch at {}: filename binds {sha256}, bytes contain {actual_sha256}; recovery is fail-closed",
                path.display()
            )));
        }
        quarantined.push(QuarantinedDelta {
            generation,
            sha256: sha256.to_string(),
            path,
            bytes,
        });
    }
    quarantined.sort_by(|left, right| {
        left.generation
            .cmp(&right.generation)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(quarantined)
}

pub(super) fn delete_quarantined_delta_exact(
    quarantined: &QuarantinedDelta,
) -> Result<(), KinDbError> {
    let current = match std::fs::read(&quarantined.path) {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to re-read quarantined delta {} before cleanup: {error}",
                quarantined.path.display()
            )));
        }
    };
    if current != quarantined.bytes {
        return Err(KinDbError::StorageError(format!(
            "quarantined delta {} changed during recovery cleanup; recovery is fail-closed",
            quarantined.path.display()
        )));
    }
    match std::fs::remove_file(&quarantined.path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to remove verified quarantined delta {}: {error}",
                quarantined.path.display()
            )));
        }
    }
    sync_parent_directory(&quarantined.path)
}

fn invalid_quarantine_name(path: &Path) -> KinDbError {
    KinDbError::StorageError(format!(
        "local delta quarantine {} has an invalid identity-bearing name; recovery is fail-closed",
        path.display()
    ))
}
