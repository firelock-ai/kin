use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{KinError, Result};

/// Repo identity stored in `.kin/manifest.json`.
///
/// This records the Kin version that created the repo, detected languages,
/// and registered adapters. It is the "birth certificate" of a Kin repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KinManifest {
    /// Kin version that created this repository.
    pub kin_version: String,

    /// Detected/configured languages in this repo.
    #[serde(default)]
    pub languages: Vec<String>,

    /// Registered assistant adapters.
    #[serde(default)]
    pub adapters: Vec<String>,

    /// Unique repository identifier (UUID v4).
    pub repo_id: String,

    /// Timestamp of repository creation.
    pub created_at: String,
}

impl KinManifest {
    /// Create a new manifest for a freshly initialized repository.
    pub fn new() -> Self {
        Self {
            kin_version: env!("CARGO_PKG_VERSION").to_string(),
            languages: Vec::new(),
            adapters: Vec::new(),
            repo_id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Load manifest from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| KinError::io(path, e))?;
        let manifest: Self = serde_json::from_str(&contents)?;
        Ok(manifest)
    }

    /// Save manifest to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(path, contents).map_err(|e| KinError::io(path, e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_manifest_has_version() {
        let manifest = KinManifest::new();
        assert_eq!(manifest.kin_version, env!("CARGO_PKG_VERSION"));
        assert!(!manifest.repo_id.is_empty());
        assert!(!manifest.created_at.is_empty());
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        let manifest = KinManifest::new();
        manifest.save(&path).unwrap();

        let loaded = KinManifest::load(&path).unwrap();
        assert_eq!(loaded.kin_version, manifest.kin_version);
        assert_eq!(loaded.repo_id, manifest.repo_id);
    }

    #[test]
    fn json_roundtrip() {
        let manifest = KinManifest::new();
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: KinManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.repo_id, manifest.repo_id);
    }
}
