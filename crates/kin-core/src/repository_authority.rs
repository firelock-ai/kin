// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Retained local repository-authority capability.
//!
//! Long-lived product processes must bind repository identity, workspace
//! identity, and the local storage root once at startup. Passing this value
//! through daemon-owned command and MCP handlers prevents a later request from
//! rediscovering mutable manifests or blessing a replaced `.kin/kindb` path.

use std::fmt;
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager, StorageBackend};
use kin_model::{RepositoryId, WorkspaceId};

use crate::{KinError, KinLayout, KinManifest, Result};

/// Startup-pinned identity and storage capability for one local repository.
#[derive(Clone)]
pub struct LocalRepositoryAuthorityBinding {
    repository_id: RepositoryId,
    workspace_id: WorkspaceId,
    backend: Arc<LocalFileBackend>,
}

impl fmt::Debug for LocalRepositoryAuthorityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRepositoryAuthorityBinding")
            .field("repository_id", &self.repository_id)
            .field("workspace_id", &self.workspace_id)
            .field("backend", &"<retained local storage capability>")
            .finish()
    }
}

impl LocalRepositoryAuthorityBinding {
    /// Bind identities already validated by a daemon to its startup-opened
    /// local storage capability.
    pub fn from_parts(
        repository_id: RepositoryId,
        workspace_id: WorkspaceId,
        backend: Arc<LocalFileBackend>,
    ) -> Self {
        Self {
            repository_id,
            workspace_id,
            backend,
        }
    }

    /// Establish a binding once for a fresh one-shot CLI/offline process.
    ///
    /// Request handlers in a long-lived daemon must receive an existing
    /// binding instead of calling this constructor.
    pub fn from_layout(layout: &KinLayout) -> Result<Self> {
        layout.check_version()?;
        let manifest = KinManifest::load(&layout.manifest_path())?;
        let repository_id = RepositoryId::new(manifest.repo_id).map_err(|error| {
            KinError::Other(format!(
                "repository manifest has an invalid repository identity: {error}"
            ))
        })?;
        let workspace_uuid = uuid::Uuid::parse_str(&manifest.workspace_id).map_err(|error| {
            KinError::Other(format!(
                "repository manifest has an invalid workspace identity: {error}"
            ))
        })?;
        let binding = Self::from_parts(
            repository_id,
            WorkspaceId::from_uuid(workspace_uuid),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        );
        binding.revalidate_pinned_namespace().map_err(|error| {
            KinError::Other(format!(
                "cannot pin repository authority namespace at startup: {error}"
            ))
        })?;
        Ok(binding)
    }

    pub fn repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }

    pub fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Revalidate the retained storage root and per-repository authority
    /// namespace without decoding the full graph snapshot.
    ///
    /// See [`revalidate_pinned_local_namespace`] for the exact property this
    /// refuses on.
    pub fn revalidate_pinned_namespace(&self) -> std::result::Result<(), kin_db::KinDbError> {
        revalidate_pinned_local_namespace(&self.backend, &self.repository_id)
    }

    /// Open a coherent authority manager through the retained storage
    /// capability.
    ///
    /// KinDB revalidates both the pinned storage-root identity and the
    /// retained per-repository namespace identity here, and retains the
    /// per-repository capability on the first successful call.
    pub fn open_manager(
        &self,
    ) -> std::result::Result<RepositoryAuthorityManager<LocalFileBackend>, kin_db::KinDbError> {
        RepositoryAuthorityManager::open(self.repository_id.clone(), Arc::clone(&self.backend))
    }
}

/// Refuse `repository_id` unless `backend` still reaches the exact storage root
/// and per-repository authority namespace it has already pinned.
///
/// KinDB retains a per-repository storage capability the first time repository
/// authority is read through a backend, keyed on the namespace directory's
/// filesystem identity, and revalidates that identity on every later access.
/// Reading authority identity through the same retained backend therefore
/// refuses a repository directory replaced at the same ambient path, a detached
/// namespace, and a store that does not hold this repository at all.
///
/// This deliberately addresses the one repository by name rather than
/// enumerating the storage root. `.kin/kindb/` also holds snapshot, vector,
/// index, and generation files beside the repository namespaces, so a listing
/// pass answers for entries that carry no authority and are not this caller's
/// concern.
///
/// Ordering is load-bearing. The first read on a fresh backend is what takes
/// the pin, so a long-lived process must take it once at startup and revalidate
/// on every later authority bind; a swap that lands before the first read
/// becomes the baseline rather than a refusal.
pub fn revalidate_pinned_local_namespace(
    backend: &LocalFileBackend,
    repository_id: &RepositoryId,
) -> std::result::Result<(), kin_db::KinDbError> {
    match backend.load_snapshot_authority(repository_id.as_str())? {
        Some(_) => Ok(()),
        None => Err(kin_db::KinDbError::StorageError(format!(
            "local storage authority does not hold repository namespace {repository_id}"
        ))),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn copy_directory(source: &std::path::Path, target: &std::path::Path) {
        std::fs::create_dir(target).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_directory(&source_path, &target_path);
            } else {
                std::fs::copy(source_path, target_path).unwrap();
            }
        }
    }

    #[test]
    fn retained_binding_rejects_identical_storage_root_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        binding.open_manager().unwrap();

        let kindb = initialized.layout.kindb_dir();
        let replacement = initialized.layout.root().join("kindb-replacement");
        let original = initialized.layout.root().join("kindb-original");
        copy_directory(&kindb, &replacement);
        std::fs::rename(&kindb, &original).unwrap();
        std::fs::rename(&replacement, &kindb).unwrap();

        let error = match binding.open_manager() {
            Ok(_) => {
                panic!("retained binding must reject an identically copied path replacement")
            }
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("changed since this backend opened"),
            "unexpected root-replacement error: {error}"
        );
    }

    #[test]
    fn retained_binding_rejects_identical_repository_namespace_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        // The pin is taken before the swap, which is what makes the replacement
        // detectable at all rather than becoming the new baseline.
        binding.open_manager().unwrap();

        let namespace = initialized
            .layout
            .kindb_dir()
            .join(binding.repository_id().as_str());
        let replacement = initialized.layout.root().join("namespace-replacement");
        let original = initialized.layout.root().join("namespace-original");
        copy_directory(&namespace, &replacement);
        std::fs::rename(&namespace, &original).unwrap();
        std::fs::rename(&replacement, &namespace).unwrap();

        let error = binding
            .revalidate_pinned_namespace()
            .expect_err("retained binding must refuse a replaced repository namespace");
        assert!(
            error.to_string().contains("refusing replacement authority"),
            "unexpected namespace-replacement revalidation error: {error}"
        );

        let error = match binding.open_manager() {
            Ok(_) => panic!("retained binding must refuse authority from a replaced namespace"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("refusing replacement authority"),
            "unexpected namespace-replacement authority error: {error}"
        );
    }

    #[test]
    fn retained_binding_rejects_detached_repository_namespace() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        binding.open_manager().unwrap();

        let namespace = initialized
            .layout
            .kindb_dir()
            .join(binding.repository_id().as_str());
        std::fs::rename(
            &namespace,
            initialized.layout.root().join("namespace-detached"),
        )
        .unwrap();

        let error = binding
            .revalidate_pinned_namespace()
            .expect_err("retained binding must refuse a detached repository namespace");
        assert!(
            error.to_string().contains("detached after this backend"),
            "unexpected detached-namespace revalidation error: {error}"
        );

        let error = match binding.open_manager() {
            Ok(_) => panic!("retained binding must refuse authority from a detached namespace"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("detached after this backend"),
            "unexpected detached-namespace authority error: {error}"
        );
    }

    #[test]
    fn binding_refuses_a_store_that_does_not_hold_its_repository() {
        let directory = tempfile::tempdir().unwrap();
        let mine_root = directory.path().join("mine");
        let other_root = directory.path().join("other");
        std::fs::create_dir_all(&mine_root).unwrap();
        std::fs::create_dir_all(&other_root).unwrap();
        let mine = crate::init(&mine_root).unwrap();
        let other = crate::init(&other_root).unwrap();
        let mine_binding = LocalRepositoryAuthorityBinding::from_layout(&mine.layout).unwrap();

        let wrong_store = LocalRepositoryAuthorityBinding::from_parts(
            mine_binding.repository_id().clone(),
            mine_binding.workspace_id(),
            Arc::new(LocalFileBackend::new(other.layout.kindb_dir())),
        );

        let error = wrong_store
            .revalidate_pinned_namespace()
            .expect_err("a binding must refuse a store that does not hold its repository");
        assert!(
            error
                .to_string()
                .contains("does not hold repository namespace"),
            "unexpected wrong-store error: {error}"
        );
    }
}
