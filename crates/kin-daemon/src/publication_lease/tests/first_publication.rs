// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Real init and filesystem persistence; GCS generation CAS uses the existing
// versioned object-store fixture. Firestore checkpointing is simulated here.
// This test does not establish live cloud or hosted route acceptance.
use super::*;
#[cfg(feature = "gcs")]
use kin_db::GcsBackend;
use kin_db::{LocalFileBackend, RepositoryAuthorityManager, StorageBackend};
use kin_model::{Hash256, RepositoryId};
use kin_remote::first_publication::{publish_first_repository, FirstPublicationMode};
use sha2::{Digest, Sha256};

const OLD_BODY: &[u8] = b"initial historical body, retained after replacement\n";
const NEW_BODY: &[u8] = b"current imported body, checked after first publication\n";

fn source(
    root: &std::path::Path,
    id: &RepositoryId,
    git_import: bool,
) -> Arc<RepositoryAuthorityManager<dyn StorageBackend>> {
    std::fs::create_dir_all(root).unwrap();
    let init = if git_import {
        git(root, &["init", "--initial-branch=main"]);
        std::fs::write(root.join("source.txt"), OLD_BODY).unwrap();
        git(root, &["add", "source.txt"]);
        git(root, &["commit", "-m", "Initial source"]);
        std::fs::write(root.join("source.txt"), NEW_BODY).unwrap();
        git(root, &["add", "source.txt"]);
        git(root, &["commit", "-m", "Update source"]);
        git(root, &["tag", "-a", "baseline", "-m", "Imported reference"]);
        kin_core::init_from_git_adopting(root, id).unwrap()
    } else {
        kin_core::init_adopting(root, id).unwrap()
    };
    let backend: Arc<dyn StorageBackend> = Arc::new(LocalFileBackend::new(init.layout.kindb_dir()));
    Arc::new(RepositoryAuthorityManager::open(id.clone(), backend).unwrap())
}

fn git(root: &std::path::Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "user.name=Publication fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn local_backend(path: &std::path::Path) -> Arc<dyn StorageBackend> {
    std::fs::create_dir_all(path).unwrap();
    Arc::new(LocalFileBackend::new(path))
}

fn hash(bytes: &[u8]) -> Hash256 {
    Hash256::from_bytes(Sha256::digest(bytes).into())
}

#[test]
fn initialized_native_first_publication_reopens_from_durable_files() {
    let temp = tempfile::tempdir().unwrap();
    let id = RepositoryId::new("private-empty").unwrap();
    let source = source(&temp.path().join("source"), &id, false);
    let expected = source.read_authority().roots().clone();
    let target = temp.path().join("published");
    let backend: Arc<dyn StorageBackend> = local_backend(&target);
    let receipt = publish_first_repository(source, &id, FirstPublicationMode::Native, backend)
        .expect("initialized native authority must publish completely");
    assert_eq!(receipt.repository_id, id);
    assert_eq!(receipt.roots, expected);
    let stored = local_backend(&target)
        .load_snapshot(id.as_str())
        .unwrap()
        .unwrap();
    assert_eq!(receipt.snapshot_sha256, hash(&stored.0));
    assert_eq!(receipt.cursor.backend_generation(), stored.1);
    let reopened = RepositoryAuthorityManager::open(id.clone(), local_backend(&target)).unwrap();
    let lease = reopened.read_authority();
    assert_eq!(lease.roots(), &expected);
    assert_eq!(lease.metadata().repository_id, id);
    assert!(lease.metadata().ref_state.default_ref.is_some());
    assert!(lease.metadata().git_external_authority.is_none());
    assert!(lease.snapshot().entities.is_empty());
}

#[cfg(feature = "gcs")]
#[tokio::test(flavor = "multi_thread")]
async fn imported_first_publication_extends_five_to_six_without_changing_old_authority() {
    let temp = tempfile::tempdir().unwrap();
    let raw = Arc::new(VersionedMemoryStore::new());
    let backend: Arc<dyn StorageBackend> =
        Arc::new(GcsBackend::from_store(Box::new(raw.clone()), "fixture"));
    let old_ids = staging_fleet();
    let mut before = BTreeMap::new();
    for name in &old_ids {
        let id = RepositoryId::new(name.clone()).unwrap();
        let source = source(&temp.path().join(name), &id, false);
        let roots = source.read_authority().roots().clone();
        publish_first_repository(source, &id, FirstPublicationMode::Native, backend.clone())
            .unwrap();
        let bytes = backend.load_snapshot(name).unwrap().unwrap().0;
        before.insert(name.clone(), (roots, bytes));
    }
    let object_store: Arc<dyn ObjectStore> = raw.clone();
    let store: Arc<dyn PublicationControlStore> = Arc::new(
        ObjectStorePublicationControlStore::new(object_store, "fixture"),
    );
    let old = PublicationControl::new(SCOPE, READER_A, old_ids.clone(), store.clone()).unwrap();
    let bootstrap = old.bootstrap_runtime_if_absent().unwrap().unwrap();
    release(&old, &bootstrap);

    let id = RepositoryId::new("private-import").unwrap();
    let imported = source(&temp.path().join("import"), &id, true);
    let imported_roots = imported.read_authority().roots().clone();
    let imported_git = imported
        .read_authority()
        .metadata()
        .git_external_authority
        .clone();
    let imported_refs =
        serde_json::to_value(&imported.read_authority().metadata().ref_state).unwrap();
    for body in [OLD_BODY, NEW_BODY] {
        assert_eq!(
            imported.load_source_blob(hash(body)).unwrap().as_deref(),
            Some(body)
        );
    }
    let mut target = old_ids.clone();
    target.push(id.to_string());
    let candidate = PublicationControl::new(SCOPE, READER_B, target.clone(), store).unwrap();
    let mut request = rollout_request_for_fleet(target.clone(), "fixture", "admit-private", None);
    request.previous_repositories = Some(old_ids.clone());
    let missing = candidate.acquire_rollout(request.clone()).unwrap_err();
    assert!(
        missing
            .to_string()
            .contains("has no graph authority object"),
        "{missing}"
    );
    for (name, (_, bytes)) in &before {
        assert_eq!(&backend.load_snapshot(name).unwrap().unwrap().0, bytes);
    }
    publish_first_repository(
        imported,
        &id,
        FirstPublicationMode::GitImported,
        backend.clone(),
    )
    .expect("complete imported authority and source bodies must publish");
    let lease = candidate.acquire_rollout(request).unwrap();
    assert_eq!(lease.authority_fence.len(), 6);
    assert_eq!(lease.fence_repositories.len(), 6);
    let lease = checkpoint_rollout_for_test(&candidate, &lease);
    candidate
        .admit_reader(AdmitReaderRequest {
            lease: proof(&lease),
            repositories: target,
            reader: ReaderAdmissionInput {
                identity: READER_B.into(),
                min_snapshot_schema: kin_db::GraphSnapshot::MIN_SUPPORTED_VERSION,
                max_snapshot_schema: kin_db::GraphSnapshot::MAX_SUPPORTED_VERSION,
                valid_for_seconds: 300,
            },
            legacy_writer_drain_proof_sha256: None,
        })
        .unwrap();
    release(&candidate, &lease);
    assert!(old
        .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
        .is_err());
    candidate
        .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
        .unwrap();
    drop(backend);
    let fresh: Arc<dyn StorageBackend> = Arc::new(GcsBackend::from_store(Box::new(raw), "fixture"));
    for (name, (roots, bytes)) in before {
        assert_eq!(fresh.load_snapshot(&name).unwrap().unwrap().0, bytes);
        let reopened =
            RepositoryAuthorityManager::open(RepositoryId::new(name).unwrap(), fresh.clone())
                .unwrap();
        assert_eq!(reopened.read_authority().roots(), &roots);
    }
    let reopened = RepositoryAuthorityManager::open(id.clone(), fresh).unwrap();
    let view = reopened.read_authority();
    assert_eq!(view.metadata().repository_id, id);
    assert_eq!(view.roots(), &imported_roots);
    assert_eq!(view.metadata().git_external_authority, imported_git);
    assert_eq!(
        serde_json::to_value(&view.metadata().ref_state).unwrap(),
        imported_refs
    );
    for body in [OLD_BODY, NEW_BODY] {
        assert_eq!(
            reopened.load_source_blob(hash(body)).unwrap().as_deref(),
            Some(body)
        );
    }
}

use crate::storage_delegate::{DelegatingBackend, StorageBackendDelegate};
use kin_db::{KinDbError, SnapshotCursor, SnapshotSaveOutcome};
use kin_remote::first_publication::FirstPublicationError;
use std::sync::atomic::AtomicBool;

#[test]
fn first_publication_refuses_identity_mode_and_uninitialized_authority() {
    let temp = tempfile::tempdir().unwrap();
    let id = RepositoryId::new("reserved-native").unwrap();
    let source = source(&temp.path().join("source"), &id, false);
    let destination: Arc<dyn StorageBackend> = local_backend(&temp.path().join("destination"));
    let other = RepositoryId::new("another-tenant").unwrap();
    assert!(publish_first_repository(
        source.clone(),
        &other,
        FirstPublicationMode::Native,
        destination.clone()
    )
    .is_err());
    assert!(publish_first_repository(
        source,
        &id,
        FirstPublicationMode::GitImported,
        destination.clone()
    )
    .is_err());
    let unborn = Arc::new(
        RepositoryAuthorityManager::open(id.clone(), local_backend(&temp.path().join("unborn")))
            .unwrap(),
    );
    assert!(publish_first_repository(
        unborn,
        &id,
        FirstPublicationMode::Native,
        destination.clone()
    )
    .is_err());
    assert!(destination.load_snapshot(id.as_str()).unwrap().is_none());
    assert!(destination.load_snapshot(other.as_str()).unwrap().is_none());
}

#[test]
fn first_publication_refuses_identical_retry_and_independent_existing_authority() {
    let temp = tempfile::tempdir().unwrap();
    let id = RepositoryId::new("reserved-existing").unwrap();
    let original = source(&temp.path().join("source"), &id, false);
    let destination: Arc<dyn StorageBackend> = local_backend(&temp.path().join("destination"));
    publish_first_repository(
        original.clone(),
        &id,
        FirstPublicationMode::Native,
        destination.clone(),
    )
    .unwrap();
    let before = destination.load_snapshot(id.as_str()).unwrap().unwrap();
    assert!(publish_first_repository(
        original,
        &id,
        FirstPublicationMode::Native,
        destination.clone()
    )
    .is_err());
    let replacement = source(&temp.path().join("replacement"), &id, true);
    assert!(publish_first_repository(
        replacement,
        &id,
        FirstPublicationMode::GitImported,
        destination.clone()
    )
    .is_err());
    assert_eq!(
        destination.load_snapshot(id.as_str()).unwrap().unwrap(),
        before
    );
}

struct DropBodies(Arc<dyn StorageBackend>);
impl StorageBackendDelegate for DropBodies {
    fn delegate(&self) -> &dyn StorageBackend {
        self.0.as_ref()
    }
    fn save_source_blob(&self, _: &str, _: [u8; 32], _: &[u8]) -> Result<(), KinDbError> {
        Ok(())
    }
}

#[test]
fn first_publication_requires_destination_body_readback_before_snapshot_cas() {
    let temp = tempfile::tempdir().unwrap();
    let id = RepositoryId::new("missing-destination-bodies").unwrap();
    let source = source(&temp.path().join("source"), &id, true);
    let durable: Arc<dyn StorageBackend> = local_backend(&temp.path().join("destination"));
    let destination: Arc<dyn StorageBackend> =
        Arc::new(DelegatingBackend::new(DropBodies(durable.clone())));
    let error =
        publish_first_repository(source, &id, FirstPublicationMode::GitImported, destination)
            .unwrap_err();
    assert!(
        matches!(error, FirstPublicationError::NotCommitted(_)),
        "{error}"
    );
    assert!(
        durable.load_snapshot(id.as_str()).unwrap().is_none(),
        "missing source bodies must not leave published authority"
    );
}

struct InspectionFailure(Arc<dyn StorageBackend>);
impl StorageBackendDelegate for InspectionFailure {
    fn delegate(&self) -> &dyn StorageBackend {
        self.0.as_ref()
    }
    fn load_snapshot_cursor(&self, _: &str) -> Result<Option<SnapshotCursor>, KinDbError> {
        Err(KinDbError::StorageError(
            "injected unknown inspection error".into(),
        ))
    }
}

#[test]
fn first_publication_does_not_treat_an_inspection_error_as_absence() {
    let temp = tempfile::tempdir().unwrap();
    let id = RepositoryId::new("unknown-destination").unwrap();
    let source = source(&temp.path().join("source"), &id, false);
    let durable: Arc<dyn StorageBackend> = local_backend(&temp.path().join("destination"));
    let destination: Arc<dyn StorageBackend> =
        Arc::new(DelegatingBackend::new(InspectionFailure(durable.clone())));
    let error = publish_first_repository(source, &id, FirstPublicationMode::Native, destination)
        .unwrap_err();
    assert!(
        matches!(error, FirstPublicationError::NotCommitted(_)),
        "{error}"
    );
    assert!(error.to_string().contains("injected unknown inspection"));
    assert!(durable.load_snapshot(id.as_str()).unwrap().is_none());
}

struct RacingPublication {
    inner: Arc<dyn StorageBackend>,
    winner: Vec<u8>,
    installed: AtomicBool,
}
impl StorageBackendDelegate for RacingPublication {
    fn delegate(&self) -> &dyn StorageBackend {
        self.inner.as_ref()
    }
    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        if !self.installed.swap(true, Ordering::SeqCst) {
            self.inner.save_snapshot(repo_id, &self.winner, 0)?;
        }
        self.inner
            .load_source_blob_bounded(repo_id, digest, max_bytes)
    }
}

#[test]
fn first_publication_initial_cas_preserves_a_winner_after_absence_inspection() {
    let temp = tempfile::tempdir().unwrap();
    let id = RepositoryId::new("racing-destination").unwrap();
    let candidate = source(&temp.path().join("source"), &id, true);
    let winner = source(&temp.path().join("winner"), &id, false);
    let winner_roots = winner.read_authority().roots().clone();
    let winner_bytes = winner.read_authority().snapshot().to_bytes().unwrap();
    let durable: Arc<dyn StorageBackend> = local_backend(&temp.path().join("destination"));
    let destination: Arc<dyn StorageBackend> =
        Arc::new(DelegatingBackend::new(RacingPublication {
            inner: durable.clone(),
            winner: winner_bytes.clone(),
            installed: AtomicBool::new(false),
        }));
    assert!(durable.load_snapshot(id.as_str()).unwrap().is_none());
    assert!(publish_first_repository(
        candidate,
        &id,
        FirstPublicationMode::GitImported,
        destination
    )
    .is_err());
    assert_eq!(
        durable.load_snapshot(id.as_str()).unwrap().unwrap().0,
        winner_bytes
    );
    let reopened = RepositoryAuthorityManager::open(id, durable).unwrap();
    assert_eq!(reopened.read_authority().roots(), &winner_roots);
}

struct LostReply(Arc<dyn StorageBackend>);
impl StorageBackendDelegate for LostReply {
    fn delegate(&self) -> &dyn StorageBackend {
        self.0.as_ref()
    }
    fn save_snapshot_classified(
        &self,
        repo_id: &str,
        data: &[u8],
        expected: SnapshotCursor,
    ) -> SnapshotSaveOutcome {
        match self.0.save_snapshot_classified(repo_id, data, expected) {
            SnapshotSaveOutcome::Committed { .. } => SnapshotSaveOutcome::Indeterminate(
                KinDbError::StorageError("injected lost committed response".into()),
            ),
            other => other,
        }
    }
}

#[test]
fn first_publication_preserves_indeterminate_outcome_and_durable_recovery_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let id = RepositoryId::new("lost-publication-response").unwrap();
    let source = source(&temp.path().join("source"), &id, false);
    let roots = source.read_authority().roots().clone();
    let durable: Arc<dyn StorageBackend> = local_backend(&temp.path().join("destination"));
    let destination: Arc<dyn StorageBackend> =
        Arc::new(DelegatingBackend::new(LostReply(durable.clone())));
    let error = publish_first_repository(
        source.clone(),
        &id,
        FirstPublicationMode::Native,
        destination,
    )
    .unwrap_err();
    assert!(
        matches!(error, FirstPublicationError::Indeterminate(_)),
        "{error}"
    );
    let reopened = RepositoryAuthorityManager::open(id.clone(), durable.clone()).unwrap();
    assert_eq!(reopened.read_authority().roots(), &roots);
    assert!(publish_first_repository(source, &id, FirstPublicationMode::Native, durable).is_err());
}
