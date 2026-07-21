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
}

/// In-memory manifest store backed by a JSON file in the .kin directory.
/// At scale, this would use kin-db entities, but for MVP a simple file works.
pub struct ManifestStore {
    manifests_dir: std::path::PathBuf,
}

impl ManifestStore {
    pub fn new(kin_dir: &std::path::Path) -> Self {
        let manifests_dir = kin_dir.join("packages").join("manifests");
        std::fs::create_dir_all(&manifests_dir).ok();
        Self { manifests_dir }
    }

    /// Get all versions of a package
    pub fn get_versions(
        &self,
        ecosystem: Ecosystem,
        package: &str,
    ) -> Result<Vec<PackageVersion>, RegistryError> {
        let id = PackageId::from_registry_name(ecosystem, package);
        let path = self.manifest_path(&id);
        if !path.exists() {
            return Ok(vec![]);
        }
        let content = std::fs::read_to_string(&path)?;
        let versions: Vec<PackageVersion> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        Ok(versions)
    }

    /// Add a new version with a crash-durable whole-file replacement.
    ///
    /// Callers that can publish concurrently must serialize the read/modify/
    /// write transaction. Replacing the complete newline-delimited manifest
    /// keeps readers from ever observing a torn append after a crash.
    pub fn add_version(&self, version: &PackageVersion) -> Result<(), RegistryError> {
        let canonical_name = version.id.canonical_name();

        // Check for duplicate
        let existing = self.get_versions(version.id.ecosystem, &canonical_name)?;
        if existing.iter().any(|v| v.version == version.version) {
            return Err(RegistryError::VersionExists(
                canonical_name,
                version.version.clone(),
            ));
        }

        let mut replacement = existing;
        replacement.push(version.clone());
        self.replace_versions(&version.id, &replacement)
    }

    /// Rewrite the full version list for a package.
    pub fn replace_versions(
        &self,
        id: &PackageId,
        versions: &[PackageVersion],
    ) -> Result<(), RegistryError> {
        let path = self.manifest_path(id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let contents = serialize_versions(versions)?;
        atomic_file::write(&path, &contents)?;
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
            std::fs::create_dir_all(parent)?;
        }
        let contents = serialize_versions(versions)?;
        atomic_file::write_with_pre_commit(&path, &contents, pre_commit)?;
        Ok(())
    }

    /// Prove that an unscoped package manifest resolves to one direct child of
    /// its ecosystem directory. Protocol adapters use this after validating a
    /// caller-controlled package name and before any manifest IO.
    pub(crate) fn manifest_path_is_direct_child(&self, id: &PackageId) -> bool {
        let mut components = std::path::Path::new(&id.name).components();
        let is_one_normal_segment = matches!(
            components.next(),
            Some(std::path::Component::Normal(segment)) if segment == std::ffi::OsStr::new(&id.name)
        ) && components.next().is_none();
        let base = self.ecosystem_manifests_dir(id.ecosystem);
        id.scope.is_none()
            && is_one_normal_segment
            && self.manifest_path(id).parent() == Some(base.as_path())
    }

    fn ecosystem_manifests_dir(&self, ecosystem: Ecosystem) -> std::path::PathBuf {
        self.manifests_dir.join(match ecosystem {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::Oci => "oci",
            Ecosystem::Go => "go",
            Ecosystem::Raw => "raw",
        })
    }

    fn manifest_path(&self, id: &PackageId) -> std::path::PathBuf {
        let base = self.ecosystem_manifests_dir(id.ecosystem);
        match &id.scope {
            Some(scope) if !scope.is_empty() => base.join(format!("@{scope}")).join(&id.name),
            _ => base.join(&id.name),
        }
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
