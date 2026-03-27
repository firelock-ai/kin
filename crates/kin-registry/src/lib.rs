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
        name: &str,
    ) -> Result<Vec<PackageVersion>, RegistryError> {
        let path = self.manifest_path(ecosystem, name);
        if !path.exists() {
            return Ok(vec![]);
        }
        let content = std::fs::read_to_string(&path)?;
        let versions: Vec<PackageVersion> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l))
            .collect::<Result<_, _>>()?;
        Ok(versions)
    }

    /// Add a new version (appends to the manifest file)
    pub fn add_version(&self, version: &PackageVersion) -> Result<(), RegistryError> {
        // Check for duplicate
        let existing = self.get_versions(version.id.ecosystem, &version.id.name)?;
        if existing.iter().any(|v| v.version == version.version) {
            return Err(RegistryError::VersionExists(
                version.id.name.clone(),
                version.version.clone(),
            ));
        }

        let path = self.manifest_path(version.id.ecosystem, &version.id.name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let line = serde_json::to_string(version)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    fn manifest_path(&self, ecosystem: Ecosystem, name: &str) -> std::path::PathBuf {
        let eco_str = match ecosystem {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::Oci => "oci",
            Ecosystem::Go => "go",
            Ecosystem::Raw => "raw",
        };
        self.manifests_dir.join(eco_str).join(name)
    }
}

pub mod cargo;
pub mod npm;
pub mod oci;
pub mod go;
