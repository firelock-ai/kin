// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Complete first publication into an unserved, previously absent repository.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kin_db::{
    Generation, KinDbError, PersistedRepositoryAuthority, RepositoryAuthorityManager,
    SnapshotCursor, SnapshotSaveOutcome, StorageBackend,
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

/// Domain separator for the canonical source-body closure digest.
///
/// Version it with the encoding beneath it. A reader in another language
/// reproduces the digest from this constant and that encoding alone.
const BODY_CLOSURE_DOMAIN: &[u8] = b"kin.first-publication-body-closure.v1\0";

/// The distinct source bodies the destination-side validator actually asked
/// for, with each body's exact length.
///
/// This is measured, not declared. It comes from the validation view that reads
/// out of the destination, so it names what the destination proved it holds
/// rather than what the source offered. An empty closure is a real value: a
/// native repository with no history references no bodies, and its digest is
/// the digest of the empty set rather than an absence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceBodyClosure {
    bodies: BTreeMap<[u8; 32], u64>,
}

impl SourceBodyClosure {
    /// Distinct referenced bodies. A digest requested twice counts once.
    pub fn body_count(&self) -> u64 {
        self.bodies.len() as u64
    }

    /// Summed length of every distinct referenced body.
    pub fn total_bytes(&self) -> u64 {
        self.bodies.values().sum()
    }

    /// Canonical digest over the closure.
    ///
    /// Domain-separated, count-prefixed, and ordered by the raw digest bytes,
    /// which is the order a `BTreeMap` keyed by `[u8; 32]` already yields. Each
    /// body contributes its digest and its little-endian length, so the value
    /// binds sizes as well as contents and stays reproducible from this
    /// function's text in any language.
    pub fn digest(&self) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(BODY_CLOSURE_DOMAIN);
        hasher.update(self.body_count().to_le_bytes());
        for (digest, length) in &self.bodies {
            hasher.update(digest);
            hasher.update(length.to_le_bytes());
        }
        Hash256::from_bytes(hasher.finalize().into())
    }
}

/// Exactly what is about to be published, offered before the irreversible CAS.
///
/// A publication whose response is lost is recoverable only against something
/// durable that was written first. This is that something: the observer runs
/// after the destination has proved it holds the complete body closure and
/// before the snapshot compare-and-swap, so a caller that persists these values
/// can tell its own completed publication from a stranger's on the next open.
/// An observer that returns an error stops the publication before the CAS.
#[derive(Debug)]
pub struct FirstPublicationIntent<'a> {
    pub repository_id: &'a RepositoryId,
    pub mode: FirstPublicationMode,
    pub roots: &'a RootBundle,
    pub snapshot_sha256: Hash256,
    pub source_closure: &'a SourceBodyClosure,
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
    publish_first_repository_observed(
        source,
        expected_repository_id,
        mode,
        destination,
        |_| Ok(()),
    )
}

/// [`publish_first_repository`], with the intended publication offered to the
/// caller before the CAS that makes it permanent.
///
/// `before_commit` runs once, after the destination has validated the complete
/// authority and its body closure out of its own storage and before the
/// snapshot compare-and-swap. Its error stops the publication with nothing
/// installed. It exists so an orchestrator can make the intended snapshot,
/// roots and closure durable first, which is the only evidence that can tell a
/// lost response apart from a foreign publication when the destination is
/// reopened. It is otherwise identical to [`publish_first_repository`], which
/// passes an observer that does nothing.
pub fn publish_first_repository_observed<B, O>(
    source: Arc<RepositoryAuthorityManager<B>>,
    expected_repository_id: &RepositoryId,
    mode: FirstPublicationMode,
    destination: Arc<dyn StorageBackend>,
    before_commit: O,
) -> Result<FirstPublicationReceipt, FirstPublicationError>
where
    B: StorageBackend + ?Sized + 'static,
    O: FnOnce(&FirstPublicationIntent<'_>) -> Result<(), FirstPublicationError>,
{
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
    // The closure is recorded on this view rather than on the copy view above,
    // because this is the view that reads out of the destination. What the
    // source was willing to hand over is not evidence; what the destination
    // answered with is.
    let (staged, referenced) =
        recording_destination_view(&repository_id, snapshot.clone(), destination.clone());
    RepositoryAuthorityManager::open(repository_id.clone(), Arc::new(staged))
        .map_err(NotCommitted)?;
    let snapshot_sha256 = Hash256::from_bytes(Sha256::digest(&*snapshot).into());
    let source_closure = SourceBodyClosure {
        bodies: lock_recovering(&referenced).clone(),
    };
    before_commit(&FirstPublicationIntent {
        repository_id: &repository_id,
        mode,
        roots: &roots,
        snapshot_sha256,
        source_closure: &source_closure,
    })?;
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
        snapshot_sha256,
        cursor,
    })
}

/// One authority reading, taken entirely from one set of snapshot bytes.
#[derive(Debug)]
pub struct PinnedAuthorityReading {
    pub roots: RootBundle,
    pub authority: PersistedRepositoryAuthority,
    pub source_closure: SourceBodyClosure,
}

/// Read a published authority and its referenced body closure from exactly the
/// snapshot bytes the caller supplies, writing nothing.
///
/// The pinning is the point. Loading a snapshot for its digest, opening the
/// destination again for its roots, and opening it a third time for its closure
/// gives three selections that no lock spans: the backend releases its lock on
/// each read, and an opened manager performs its own recovery over acknowledged
/// journal frames while a snapshot load returns only the base. A writer that
/// advances the destination between those calls therefore produces a reading
/// whose digest belongs to one authority and whose roots and refs belong to
/// another, and every field of it looks measured.
///
/// So there is one read here. The caller supplies the exact bytes it hashed, and
/// the roots, the metadata and the closure all come from those bytes through a
/// view that reports no journal frames at all, which is what makes an
/// acknowledged advance unable to leak into this reading. Only the bodies are
/// read from the destination, deliberately, because a body's presence there is
/// the thing being proved.
///
/// The view is read-only: every write method on it refuses. Nothing here
/// creates, repairs or replaces destination state.
pub fn read_pinned_published_authority(
    repository_id: &RepositoryId,
    destination: Arc<dyn StorageBackend>,
    snapshot: Arc<Vec<u8>>,
) -> Result<PinnedAuthorityReading, FirstPublicationError> {
    use FirstPublicationError::Indeterminate;
    let (view, referenced) = recording_destination_view(repository_id, snapshot, destination);
    let pinned = RepositoryAuthorityManager::open(repository_id.clone(), Arc::new(view))
        .map_err(Indeterminate)?;
    let lease = pinned.read_authority();
    let roots = lease.roots().clone();
    let authority = lease.metadata().clone();
    drop(lease);
    let source_closure = SourceBodyClosure {
        bodies: lock_recovering(&referenced).clone(),
    };
    Ok(PinnedAuthorityReading {
        roots,
        authority,
        source_closure,
    })
}

/// A validation view over `destination`, recording every body it answers with.
///
/// One builder for both callers on purpose. A publication records the closure
/// it is about to commit and a recovery records the closure that is already
/// there, and the two values are only comparable while they are produced by the
/// same walk over the same kind of view.
type ReferencedBodies = Arc<Mutex<BTreeMap<[u8; 32], u64>>>;

fn recording_destination_view(
    repository_id: &RepositoryId,
    snapshot: Arc<Vec<u8>>,
    destination: Arc<dyn StorageBackend>,
) -> (SnapshotBodyReader, ReferencedBodies) {
    let referenced: ReferencedBodies = Arc::new(Mutex::new(BTreeMap::new()));
    let recorder = referenced.clone();
    let read_id = repository_id.clone();
    let view = SnapshotBodyReader {
        repository_id: repository_id.clone(),
        snapshot,
        read_body: Box::new(move |digest, max_bytes| {
            let body = destination.load_source_blob_bounded(read_id.as_str(), digest, max_bytes)?;
            if let Some(body) = body.as_ref() {
                lock_recovering(&recorder).insert(digest, body.len() as u64);
            }
            Ok(body)
        }),
    };
    (view, referenced)
}

/// Take a lock this module fully owns, recovering rather than panicking.
///
/// The only holder inserts into a map, so it cannot panic while holding the
/// lock and the poisoned arm is unreachable in practice. Recovering anyway
/// keeps a publication from turning an impossible lock state into a panic in
/// the middle of a body walk.
fn lock_recovering(
    bodies: &Mutex<BTreeMap<[u8; 32], u64>>,
) -> MutexGuard<'_, BTreeMap<[u8; 32], u64>> {
    bodies.lock().unwrap_or_else(PoisonError::into_inner)
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
