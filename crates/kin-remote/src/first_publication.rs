// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Complete first publication into an unserved, previously absent repository.

use std::sync::Arc;

use kin_db::{
    Generation, KinDbError, RepositoryAuthorityManager, SnapshotCursor, SnapshotSaveOutcome,
    StorageBackend,
};
use kin_model::{Hash256, RepositoryId, RootBundle};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstPublicationMode {
    Native,
    GitImported,
}

#[derive(Debug)]
pub struct FirstPublicationReceipt {
    pub repository_id: RepositoryId,
    pub roots: RootBundle,
    pub snapshot_sha256: Hash256,
    pub cursor: SnapshotCursor,
}

#[derive(Debug, thiserror::Error)]
pub enum FirstPublicationError {
    #[error("first publication refused: {0}")]
    Refused(String),
    #[error("first publication did not commit: {0}")]
    NotCommitted(#[source] KinDbError),
    #[error("first publication requires durable readback: {0}")]
    Indeterminate(#[source] KinDbError),
}

/// Copy one initialized authority without changing its identity or history.
///
/// The caller must own a reserved, unserved destination ID. This primitive
/// grants no tenant access or fleet admission. Bodies become durable before
/// the complete authority's create-if-absent CAS. A fresh authority open and
/// exact snapshot/cursor readback precede the receipt. A retry against an
/// existing publication is refused, including an identical prior attempt;
/// the orchestrator must resolve a lost receipt through durable readback.
///
/// Source-body requirements come from kin-db's full authority validator. A
/// private validation view copies each requested immutable body, then another
/// view validates those bodies from destination storage before publication.
/// Neither view is evidence of durability; only the destination CAS and reopen
/// can establish that. No checkout, Git directory or derived index is read.
pub fn publish_first_repository<B: StorageBackend + ?Sized + 'static>(
    source: Arc<RepositoryAuthorityManager<B>>,
    expected_repository_id: &RepositoryId,
    mode: FirstPublicationMode,
    destination: Arc<dyn StorageBackend>,
) -> Result<FirstPublicationReceipt, FirstPublicationError> {
    use FirstPublicationError::{Indeterminate, NotCommitted, Refused};
    let lease = source.read_authority();
    let metadata = lease
        .snapshot()
        .repository_authority
        .as_ref()
        .ok_or_else(|| Refused("source has no repository authority".into()))?;
    if &metadata.repository_id != expected_repository_id {
        return Err(Refused(
            "source does not own the reserved repository identity".into(),
        ));
    }
    if lease.roots().generation == 0 || metadata.ref_state.default_ref.is_none() {
        return Err(Refused(
            "source must be initialized with a default ref".into(),
        ));
    }
    if metadata.git_external_authority.is_some() != (mode == FirstPublicationMode::GitImported) {
        return Err(Refused(
            "source does not match the declared native or Git-import mode".into(),
        ));
    }
    let roots = lease.roots().clone();
    let snapshot = Arc::new(lease.snapshot().to_bytes().map_err(NotCommitted)?);
    drop(lease);
    if destination
        .load_snapshot_cursor(expected_repository_id.as_str())
        .map_err(NotCommitted)?
        .is_some()
    {
        return Err(Refused("destination already holds a publication".into()));
    }
    let repository_id = expected_repository_id.clone();
    let copy_destination = destination.clone();
    let copy_id = repository_id.clone();
    let copy = SnapshotBodyReader {
        repository_id: repository_id.clone(),
        snapshot: snapshot.clone(),
        read_body: Box::new(move |digest, max_bytes| {
            let Some(body) = source.load_source_blob(Hash256::from_bytes(digest))? else {
                return Ok(None);
            };
            if body.len() as u64 > max_bytes {
                return Err(KinDbError::StorageError(
                    "publication source body exceeds validator bound".into(),
                ));
            }
            copy_destination.save_source_blob(copy_id.as_str(), digest, &body)?;
            Ok(Some(body))
        }),
    };
    RepositoryAuthorityManager::open(repository_id.clone(), Arc::new(copy))
        .map_err(NotCommitted)?;
    let read_destination = destination.clone();
    let read_id = repository_id.clone();
    let staged = SnapshotBodyReader {
        repository_id: repository_id.clone(),
        snapshot: snapshot.clone(),
        read_body: Box::new(move |digest, max_bytes| {
            read_destination.load_source_blob_bounded(read_id.as_str(), digest, max_bytes)
        }),
    };
    RepositoryAuthorityManager::open(repository_id.clone(), Arc::new(staged))
        .map_err(NotCommitted)?;
    let cursor = match destination.save_snapshot_classified(
        repository_id.as_str(),
        &snapshot,
        SnapshotCursor::INITIAL,
    ) {
        SnapshotSaveOutcome::Committed { cursor } => cursor,
        SnapshotSaveOutcome::NotCommitted(error) => return Err(NotCommitted(error)),
        SnapshotSaveOutcome::Indeterminate(error) => return Err(Indeterminate(error)),
    };
    let reopened = RepositoryAuthorityManager::open(repository_id.clone(), destination.clone())
        .map_err(Indeterminate)?;
    if reopened.read_authority().roots() != &roots {
        return Err(Indeterminate(KinDbError::StorageError(
            "published authority roots changed before verification".into(),
        )));
    }
    let observed = destination
        .load_snapshot(repository_id.as_str())
        .map_err(Indeterminate)?;
    if !observed.is_some_and(|(bytes, generation)| {
        bytes == *snapshot && generation == cursor.backend_generation()
    }) {
        return Err(Indeterminate(KinDbError::StorageError(
            "published snapshot or cursor changed before verification".into(),
        )));
    }
    Ok(FirstPublicationReceipt {
        repository_id,
        roots,
        snapshot_sha256: Hash256::from_bytes(Sha256::digest(&*snapshot).into()),
        cursor,
    })
}

type BodyRead = dyn Fn([u8; 32], u64) -> Result<Option<Vec<u8>>, KinDbError> + Send + Sync;

// A read-only validation view, never a destination or a durable publication.
// There is no journal or cached history proof, so open validates the full
// supplied authority and asks the body reader for its complete closure.
struct SnapshotBodyReader {
    repository_id: RepositoryId,
    snapshot: Arc<Vec<u8>>,
    read_body: Box<BodyRead>,
}

impl SnapshotBodyReader {
    fn check_id(&self, id: &str) -> Result<(), KinDbError> {
        if id != self.repository_id.as_str() {
            return Err(KinDbError::StorageError(
                "publication validation namespace mismatch".into(),
            ));
        }
        Ok(())
    }
}

fn read_only<T>() -> Result<T, KinDbError> {
    Err(KinDbError::StorageError(
        "publication validation view is read-only".into(),
    ))
}

impl StorageBackend for SnapshotBodyReader {
    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        Ok(vec![self.repository_id.to_string()])
    }
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        self.check_id(repo_id)?;
        Ok(Some((self.snapshot.as_ref().clone(), 1)))
    }
    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.check_id(repo_id)?;
        (self.read_body)(digest, max_bytes)
    }
    fn load_deltas_since(
        &self,
        repo_id: &str,
        _: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        self.check_id(repo_id)?;
        Ok(Vec::new())
    }
    fn load_overlay(&self, repo_id: &str, _: &str) -> Result<Option<Vec<u8>>, KinDbError> {
        self.check_id(repo_id)?;
        Ok(None)
    }
    fn save_snapshot(&self, _: &str, _: &[u8], _: Generation) -> Result<Generation, KinDbError> {
        read_only()
    }
    fn save_delta(&self, _: &str, _: &[u8], _: Generation) -> Result<Generation, KinDbError> {
        read_only()
    }
    fn clear_deltas(&self, _: &str) -> Result<(), KinDbError> {
        read_only()
    }
    fn save_overlay(&self, _: &str, _: &str, _: &[u8]) -> Result<(), KinDbError> {
        read_only()
    }
    fn delete_overlay(&self, _: &str, _: &str) -> Result<(), KinDbError> {
        read_only()
    }
}
