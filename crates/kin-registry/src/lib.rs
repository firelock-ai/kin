// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Kin Registry -- package serving for the KinLab platform.
//!
//! Every artifact system is three layers:
//! 1. Blob store (kin-blobs) -- content-addressable storage
//! 2. Manifest store -- name x version -> blob hash + metadata
//! 3. Protocol adapter -- HTTP endpoints per ecosystem (Cargo, npm, OCI, Go)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod atomic_file;
mod storage_lock;

/// Package ecosystem identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo,
    Npm,
    Oci,
    Go,
    Raw,
}

/// Universal package identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageId {
    pub ecosystem: Ecosystem,
    pub scope: Option<String>,
    pub name: String,
}

impl PackageId {
    /// Canonical registry-facing package name.
    pub fn canonical_name(&self) -> String {
        match &self.scope {
            Some(scope) if !scope.is_empty() => format!("@{scope}/{}", self.name),
            _ => self.name.clone(),
        }
    }

    /// Parse a registry-facing package name into the internal identity shape.
    pub fn from_registry_name(ecosystem: Ecosystem, package: &str) -> Self {
        if ecosystem == Ecosystem::Npm {
            if let Some(scoped) = package.strip_prefix('@') {
                if let Some((scope, name)) = scoped.split_once('/') {
                    if !scope.is_empty() && !name.is_empty() {
                        return Self {
                            ecosystem,
                            scope: Some(scope.to_string()),
                            name: name.to_string(),
                        };
                    }
                }
            }
        }

        Self {
            ecosystem,
            scope: None,
            name: package.to_string(),
        }
    }
}

/// A published version of a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVersion {
    pub id: PackageId,
    pub version: String,
    pub blob_hash: String,
    pub blob_size: u64,
    pub checksum: String,
    pub metadata: serde_json::Value,
    pub published_at: DateTime<Utc>,
    pub published_by: String,
    pub yanked: bool,
}

/// Registry errors
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("package not found: {0}")]
    NotFound(String),
    #[error("version already exists: {0}@{1}")]
    VersionExists(String, String),
    #[error("storage error: {0}")]
    Storage(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid registry operation: {0}")]
    InvalidOperation(String),
}

/// In-memory manifest store backed by a JSON file in the .kin directory.
/// At scale, this would use kin-db entities, but for MVP a simple file works.
#[derive(Clone)]
pub struct ManifestStore {
    manifests_dir: std::path::PathBuf,
    authority: atomic_file::AuthorityRoot,
}

/// Shared-lock view of one ecosystem's durable manifest authority.
pub(crate) struct ManifestReadTransaction<'a> {
    store: &'a ManifestStore,
    ecosystem: Ecosystem,
    _lock: storage_lock::StorageLock,
}

/// Exclusive-lock view used for blob + manifest publication transactions.
///
/// Protocol adapters must keep this value alive from their immutable-version
/// preflight through blob publication and the final manifest replacement.
pub(crate) struct ManifestWriteTransaction<'a> {
    store: &'a ManifestStore,
    ecosystem: Ecosystem,
    _lock: storage_lock::StorageLock,
}

impl ManifestStore {
    pub fn new(kin_dir: &std::path::Path) -> Self {
        let configured = kin_dir.join("packages").join("manifests");
        let authority = atomic_file::AuthorityRoot::new(&configured);
        let manifests_dir = authority.path().to_path_buf();
        Self {
            manifests_dir,
            authority,
        }
    }

    pub(crate) fn read_transaction(
        &self,
        ecosystem: Ecosystem,
    ) -> Result<ManifestReadTransaction<'_>, RegistryError> {
        let lock = storage_lock::StorageLock::shared_at(
            &self.authority,
            &self.transaction_lock_relative(ecosystem),
        )?;
        Ok(ManifestReadTransaction {
            store: self,
            ecosystem,
            _lock: lock,
        })
    }

    pub(crate) fn write_transaction(
        &self,
        ecosystem: Ecosystem,
    ) -> Result<ManifestWriteTransaction<'_>, RegistryError> {
        let lock = storage_lock::StorageLock::exclusive_at(
            &self.authority,
            &self.transaction_lock_relative(ecosystem),
        )?;
        Ok(ManifestWriteTransaction {
            store: self,
            ecosystem,
            _lock: lock,
        })
    }

    /// Get all versions of a package
    pub fn get_versions(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Vec<PackageVersion>, RegistryError> {
        self.read_transaction(ecosystem)?.get_versions(package)
    }

    fn get_versions_unlocked(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Vec<PackageVersion>, RegistryError> {
        let id = PackageId::from_registry_name(ecosystem, package);
        if !self.manifest_path_is_contained(&id) {
            return Err(RegistryError::InvalidOperation(
                "package manifest path escaped its ecosystem directory".to_string(),
            ));
        }
        let relative = self.manifest_relative_path(&id);
        let content = match self.authority.read(&relative) {
            Ok(content) => String::from_utf8(content).map_err(|error| {
                RegistryError::InvalidOperation(format!(
                    "package manifest is not valid UTF-8: {error}"
                ))
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(error.into()),
        };
        let versions: Vec<PackageVersion> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        Ok(versions)
    }

    fn snapshots_root(&self) -> std::path::PathBuf {
        self.manifests_dir
            .parent()
            .map(|parent| parent.join("manifest-snapshots"))
            .unwrap_or_else(|| self.manifests_dir.join("manifest-snapshots"))
    }

    /// Copy every manifest file of one ecosystem into a fresh timestamped
    /// snapshot directory outside the served tree, returning its path.
    fn snapshot_ecosystem_unlocked(
        &self,
        ecosystem: Ecosystem,
    ) -> Result<std::path::PathBuf, RegistryError> {
        let names = self.list_packages_unlocked(ecosystem)?;
        let stamp = Utc::now().format("%Y%m%dT%H%M%S%3fZ");
        let dest = self
            .snapshots_root()
            .join(format!("{}-{stamp}", ecosystem_dir_name(ecosystem)));
        std::fs::create_dir_all(&dest)?;
        for name in &names {
            let relative = std::path::Path::new(ecosystem_dir_name(ecosystem)).join(name);
            let bytes = self.authority.read(&relative)?;
            std::fs::write(dest.join(name), bytes)?;
        }
        Ok(dest)
    }

    /// Rewrite every manifest file recorded in a snapshot back into the served
    /// tree through the atomic authority writer. Only files present in the
    /// snapshot are touched; repair never creates packages, so restoring the
    /// snapshotted files reverses it completely.
    fn restore_ecosystem_unlocked(
        &self,
        ecosystem: Ecosystem,
        snapshot: &std::path::Path,
    ) -> Result<usize, RegistryError> {
        let mut restored = 0usize;
        for entry in std::fs::read_dir(snapshot)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let bytes = std::fs::read(entry.path())?;
            let relative = std::path::Path::new(ecosystem_dir_name(ecosystem)).join(&name);
            self.authority.write(&relative, &bytes)?;
            restored += 1;
        }
        Ok(restored)
    }

    /// Best-effort removal of the oldest snapshots beyond `keep`. The stamp
    /// format sorts lexicographically in time order.
    fn prune_ecosystem_snapshots_unlocked(&self, ecosystem: Ecosystem, keep: usize) {
        let prefix = format!("{}-", ecosystem_dir_name(ecosystem));
        let Ok(entries) = std::fs::read_dir(self.snapshots_root()) else {
            return;
        };
        let mut dirs: Vec<std::path::PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect();
        dirs.sort();
        while dirs.len() > keep {
            let oldest = dirs.remove(0);
            let _ = std::fs::remove_dir_all(&oldest);
        }
    }

    fn list_packages_unlocked(&self, ecosystem: Ecosystem) -> Result<Vec<String>, RegistryError> {
        let relative = std::path::PathBuf::from(ecosystem_dir_name(ecosystem));
        let names = match self.authority.read_dir_names(&relative) {
            Ok(names) => names,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(error.into()),
        };
        let mut packages: Vec<String> = names
            .into_iter()
            .filter_map(|name| name.into_string().ok())
            .filter(|name| !name.starts_with('.'))
            .collect();
        packages.sort();
        Ok(packages)
    }

    /// Add a new version with a crash-durable whole-file replacement.
    ///
    /// Callers that can publish concurrently must serialize the read/modify/
    /// write transaction. Replacing the complete newline-delimited manifest
    /// keeps readers from ever observing a torn append after a crash.
    pub fn add_version(&self, version: &PackageVersion) -> Result<(), RegistryError> {
        self.write_transaction(version.id.ecosystem)?
            .add_version(version)
    }

    /// Rewrite the full version list for a package.
    pub fn replace_versions(
        &self,
        id: &PackageId,
        versions: &[PackageVersion],
    ) -> Result<(), RegistryError> {
        self.write_transaction(id.ecosystem)?
            .replace_versions(id, versions)
    }

    /// List package manifest names that are direct children of one
    /// ecosystem's manifest directory. Scoped ecosystems (npm) surface their
    /// scope directories as entries, so callers needing scoped coverage must
    /// descend; the Cargo ecosystem is always unscoped and therefore complete.
    pub fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<String>, RegistryError> {
        self.read_transaction(ecosystem)?.list_packages()
    }

    fn replace_versions_unlocked(
        &self,
        id: &PackageId,
        versions: &[PackageVersion],
    ) -> Result<(), RegistryError> {
        if !self.manifest_path_is_contained(id) {
            return Err(RegistryError::InvalidOperation(
                "package manifest path escaped its ecosystem directory".to_string(),
            ));
        }
        let relative = self.manifest_relative_path(id);
        let contents = serialize_versions(versions)?;
        self.authority.write(&relative, &contents)?;
        Ok(())
    }

    #[cfg(test)]
    fn replace_versions_with_pre_commit<F>(
        &self,
        id: &PackageId,
        versions: &[PackageVersion],
        pre_commit: F,
    ) -> Result<(), RegistryError>
    where
        F: FnOnce(&std::path::Path) -> std::io::Result<()>,
    {
        let path = self.manifest_path(id);
        if let Some(parent) = path.parent() {
            atomic_file::ensure_directory_durable(parent)?;
        }
        let contents = serialize_versions(versions)?;
        atomic_file::write_with_pre_commit(&path, &contents, pre_commit)?;
        Ok(())
    }

    /// Prove that an unscoped package manifest resolves to one direct child of
    /// its ecosystem directory. Protocol adapters use this after validating a
    /// caller-controlled package name and before any manifest IO.
    pub(crate) fn manifest_path_is_direct_child(&self, id: &PackageId) -> bool {
        let is_one_normal_segment = is_one_normal_path_segment(&id.name);
        let base = self.ecosystem_manifests_dir(id.ecosystem);
        id.scope.is_none()
            && is_one_normal_segment
            && self.manifest_path(id).parent() == Some(base.as_path())
    }

    fn manifest_path_is_contained(&self, id: &PackageId) -> bool {
        let base = self.ecosystem_manifests_dir(id.ecosystem);
        let shape_is_valid = match id.ecosystem {
            Ecosystem::Npm => match id.scope.as_deref() {
                Some(scope) if !scope.is_empty() && is_one_normal_path_segment(scope) => {
                    is_one_normal_path_segment(&id.name)
                }
                Some(_) => false,
                None => is_one_normal_path_segment(&id.name),
            },
            // Go module names are intentionally multi-segment. Validate every
            // segment lexically before projecting the logical coordinate to
            // the manifest hierarchy.
            Ecosystem::Go => id.scope.is_none() && is_safe_relative_path(&id.name),
            Ecosystem::Cargo | Ecosystem::Oci | Ecosystem::Raw => {
                id.scope.is_none() && is_one_normal_path_segment(&id.name)
            }
        };
        if !shape_is_valid {
            return false;
        }

        let path = self.manifest_path(id);
        path != base && path.starts_with(&base)
    }

    fn ecosystem_manifests_dir(&self, ecosystem: Ecosystem) -> std::path::PathBuf {
        self.manifests_dir.join(ecosystem_dir_name(ecosystem))
    }

    fn transaction_lock_relative(&self, ecosystem: Ecosystem) -> std::path::PathBuf {
        let name = match ecosystem {
            Ecosystem::Cargo => "cargo.lock",
            Ecosystem::Npm => "npm.lock",
            Ecosystem::Oci => "oci.lock",
            Ecosystem::Go => "go.lock",
            Ecosystem::Raw => "raw.lock",
        };
        std::path::PathBuf::from(".transactions").join(name)
    }

    fn manifest_relative_path(&self, id: &PackageId) -> std::path::PathBuf {
        let ecosystem = ecosystem_dir_name(id.ecosystem);
        match &id.scope {
            Some(scope) if !scope.is_empty() => std::path::PathBuf::from(ecosystem)
                .join(format!("@{scope}"))
                .join(&id.name),
            _ => std::path::PathBuf::from(ecosystem).join(&id.name),
        }
    }

    fn manifest_path(&self, id: &PackageId) -> std::path::PathBuf {
        let base = self.ecosystem_manifests_dir(id.ecosystem);
        match &id.scope {
            Some(scope) if !scope.is_empty() => base.join(format!("@{scope}")).join(&id.name),
            _ => base.join(&id.name),
        }
    }
}

fn is_one_normal_path_segment(value: &str) -> bool {
    let mut components = std::path::Path::new(value).components();
    matches!(
        components.next(),
        Some(std::path::Component::Normal(segment)) if segment == std::ffi::OsStr::new(value)
    ) && components.next().is_none()
}

fn is_safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && is_one_normal_path_segment(segment))
}

fn ecosystem_dir_name(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Cargo => "cargo",
        Ecosystem::Npm => "npm",
        Ecosystem::Oci => "oci",
        Ecosystem::Go => "go",
        Ecosystem::Raw => "raw",
    }
}

impl ManifestReadTransaction<'_> {
    pub(crate) fn get_versions(&self, package: &str) -> Result<Vec<PackageVersion>, RegistryError> {
        self.store.get_versions_unlocked(self.ecosystem, package)
    }

    pub(crate) fn list_packages(&self) -> Result<Vec<String>, RegistryError> {
        self.store.list_packages_unlocked(self.ecosystem)
    }
}

impl ManifestWriteTransaction<'_> {
    pub(crate) fn get_versions(&self, package: &str) -> Result<Vec<PackageVersion>, RegistryError> {
        self.store.get_versions_unlocked(self.ecosystem, package)
    }

    pub(crate) fn list_packages(&self) -> Result<Vec<String>, RegistryError> {
        self.store.list_packages_unlocked(self.ecosystem)
    }

    pub(crate) fn snapshot(&self) -> Result<std::path::PathBuf, RegistryError> {
        self.store.snapshot_ecosystem_unlocked(self.ecosystem)
    }

    pub(crate) fn restore(&self, snapshot: &std::path::Path) -> Result<usize, RegistryError> {
        self.store
            .restore_ecosystem_unlocked(self.ecosystem, snapshot)
    }

    pub(crate) fn prune_snapshots(&self, keep: usize) {
        self.store
            .prune_ecosystem_snapshots_unlocked(self.ecosystem, keep);
    }

    pub(crate) fn add_version(&self, version: &PackageVersion) -> Result<(), RegistryError> {
        if version.id.ecosystem != self.ecosystem {
            return Err(RegistryError::InvalidOperation(
                "manifest transaction ecosystem does not match package".to_string(),
            ));
        }
        let canonical_name = version.id.canonical_name();
        let mut existing = self.get_versions(&canonical_name)?;
        if existing
            .iter()
            .any(|candidate| candidate.version == version.version)
        {
            return Err(RegistryError::VersionExists(
                canonical_name,
                version.version.clone(),
            ));
        }
        existing.push(version.clone());
        self.store.replace_versions_unlocked(&version.id, &existing)
    }

    pub(crate) fn replace_versions(
        &self,
        id: &PackageId,
        versions: &[PackageVersion],
    ) -> Result<(), RegistryError> {
        if id.ecosystem != self.ecosystem {
            return Err(RegistryError::InvalidOperation(
                "manifest transaction ecosystem does not match package".to_string(),
            ));
        }
        self.store.replace_versions_unlocked(id, versions)
    }
}

fn serialize_versions(versions: &[PackageVersion]) -> Result<Vec<u8>, RegistryError> {
    let mut contents = Vec::new();
    for version in versions {
        let line = serde_json::to_string(version)?;
        contents.extend_from_slice(line.as_bytes());
        contents.push(b'\n');
    }
    Ok(contents)
}

pub mod cargo;
pub mod go;
pub mod npm;
pub mod oci;

#[cfg(test)]
mod tests {
    use super::*;

    fn cargo_version(version: &str) -> PackageVersion {
        PackageVersion {
            id: PackageId {
                ecosystem: Ecosystem::Cargo,
                scope: None,
                name: "demo".to_string(),
            },
            version: version.to_string(),
            blob_hash: format!("hash-{version}"),
            blob_size: 1,
            checksum: format!("checksum-{version}"),
            metadata: serde_json::json!({
                "cargo_index_format": 1,
                "features": {},
                "deps": [],
            }),
            published_at: Utc::now(),
            published_by: "test".to_string(),
            yanked: false,
        }
    }

    #[test]
    fn failed_cargo_manifest_commit_preserves_prior_authority_and_cleans_stage() {
        let root = tempfile::tempdir().unwrap();
        let store = ManifestStore::new(root.path());
        let first = cargo_version("0.1.0");
        let second = cargo_version("0.2.0");
        store.add_version(&first).unwrap();
        let path = store.manifest_path(&first.id);
        let original = std::fs::read(&path).unwrap();

        let error = store
            .replace_versions_with_pre_commit(&first.id, &[first.clone(), second], |_| {
                Err(std::io::Error::other("injected before manifest rename"))
            })
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("injected before manifest rename"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            store.get_versions(Ecosystem::Cargo, "demo").unwrap().len(),
            1
        );
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    }
}
