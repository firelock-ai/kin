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
        binding.pin_local_namespace().map_err(|error| {
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

    /// Pin and validate the exact local storage root and repository namespace
    /// without decoding the full graph snapshot.
    ///
    /// KinDB's capability-backed repository listing retains both identities;
    /// later `open_manager` calls therefore reject a root or per-repository
    /// directory that was swapped after process startup.
    pub fn pin_local_namespace(&self) -> std::result::Result<(), kin_db::KinDbError> {
        let repositories = self.backend.list_repos()?;
        if repositories
            .iter()
            .any(|repository| repository == self.repository_id.as_str())
        {
            Ok(())
        } else {
            Err(kin_db::KinDbError::StorageError(format!(
                "local storage authority has no repository namespace {}",
                self.repository_id
            )))
        }
    }

    /// Open a coherent authority manager through the retained storage
    /// capability. KinDB revalidates the pinned storage-root identity here.
    pub fn open_manager(
        &self,
    ) -> std::result::Result<RepositoryAuthorityManager<LocalFileBackend>, kin_db::KinDbError> {
        RepositoryAuthorityManager::open(self.repository_id.clone(), Arc::clone(&self.backend))
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
}
