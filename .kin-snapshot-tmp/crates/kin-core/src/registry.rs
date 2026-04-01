// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Global Kin registry at `~/.kin/registry.toml`.
//!
//! Lets MCP servers and cross-repo queries discover all Kin repositories on
//! disk regardless of where they live.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct KinRegistry {
    pub repos: Vec<RegisteredRepo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredRepo {
    pub id: String,
    pub path: PathBuf,
    pub entities: usize,
    pub last_commit: String, // ISO 8601
    #[serde(default)]
    pub dependencies: Vec<crate::dependencies::RepoDependency>,
}

impl KinRegistry {
    /// Load from `~/.kin/registry.toml`, or return empty if it doesn't exist.
    ///
    /// Acquires a shared (read) lock to prevent reading a partially-written file.
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Self::load_from(&registry_path())
    }

    /// Load from a specific path (for testing).
    ///
    /// Acquires a shared (read) lock on the corresponding `.lock` file.
    pub fn load_from(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let lock_path = path.with_extension("lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        lock_file.lock_shared()?;
        let content = std::fs::read_to_string(path)?;
        // Lock released on drop
        Ok(toml::from_str(&content)?)
    }

    /// Save to `~/.kin/registry.toml`.
    ///
    /// Acquires an exclusive lock, writes atomically (tmp → rename).
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.save_to(&registry_path())
    }

    /// Save to a specific path (for testing).
    ///
    /// Acquires an exclusive lock, writes atomically (tmp → rename)
    /// so concurrent readers never see a partial file.
    pub fn save_to(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock_path = path.with_extension("lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        lock_file.lock_exclusive()?;

        // Atomic write: write to tmp, then rename into place.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, toml::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;

        // Lock released on drop
        Ok(())
    }

    /// Register or update a repo entry.
    ///
    /// Automatically detects cross-repo dependencies from manifest files
    /// (`Cargo.toml`, `package.json`, `go.mod`) located at `path`.
    ///
    /// If `remote_repo_ids` is provided, dependency detection also matches
    /// against repos known to the remote spine (KinLab). This enables
    /// detecting dependencies on repos the user doesn't have locally.
    pub fn upsert(&mut self, id: String, path: PathBuf, entities: usize) {
        self.upsert_with_remote(id, path, entities, &[]);
    }

    /// Register or update, with additional remote repo IDs for dependency matching.
    pub fn upsert_with_remote(
        &mut self,
        id: String,
        path: PathBuf,
        entities: usize,
        remote_repo_ids: &[String],
    ) {
        let now = chrono::Utc::now().to_rfc3339();
        // Combine local + remote repo IDs for dependency detection.
        let mut all_ids: Vec<String> = self.repos.iter().map(|r| r.id.clone()).collect();
        for remote_id in remote_repo_ids {
            if !all_ids.contains(remote_id) {
                all_ids.push(remote_id.clone());
            }
        }
        let deps = crate::dependencies::detect_dependencies_with_registry(&path, &all_ids);
        if let Some(existing) = self.repos.iter_mut().find(|r| r.id == id) {
            existing.path = path;
            existing.entities = entities;
            existing.last_commit = now;
            existing.dependencies = deps;
        } else {
            self.repos.push(RegisteredRepo {
                id,
                path,
                entities,
                last_commit: now,
                dependencies: deps,
            });
        }
    }

    /// Resolve the remote spine URL from config, if any.
    ///
    /// Checks (in order):
    /// 1. `KIN_REMOTE_URL` env var
    /// 2. `~/.kin/remote.toml` `url = "..."` field
    ///
    /// Returns None if no remote is configured.
    pub fn remote_url() -> Option<String> {
        if let Ok(url) = std::env::var("KIN_REMOTE_URL") {
            if !url.is_empty() {
                return Some(url);
            }
        }
        let config_path = Self::kin_dir().join("remote.toml");
        let content = std::fs::read_to_string(&config_path).ok()?;
        let parsed: toml::Table = content.parse().ok()?;
        parsed
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Parse a JSON response body into a list of repo IDs.
    /// Accepts either `[{"id": "repo-a"}, ...]` or `["repo-a", ...]`.
    pub fn parse_repo_catalog(body: &str) -> Vec<String> {
        // Try array of objects with "id" field first.
        if let Ok(repos) = serde_json::from_str::<Vec<serde_json::Value>>(body) {
            let ids: Vec<String> = repos
                .iter()
                .filter_map(|r| r.get("id").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .collect();
            if !ids.is_empty() {
                return ids;
            }
        }
        // Fallback: simple string array.
        serde_json::from_str::<Vec<String>>(body).unwrap_or_default()
    }

    fn kin_dir() -> PathBuf {
        directories::BaseDirs::new()
            .map(|b| b.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".kin")
    }

    /// Build the cross-repo dependency graph: repo ID → [provider repo IDs].
    pub fn dependency_graph(&self) -> HashMap<String, Vec<String>> {
        crate::dependencies::dependency_graph(&self.repos)
    }

    /// Remove entries whose paths no longer contain a `.kin/` directory.
    pub fn clean(&mut self) -> usize {
        let before = self.repos.len();
        self.repos.retain(|r| r.path.join(".kin").exists());
        before - self.repos.len()
    }

    /// Get all registered repo paths.
    pub fn repo_paths(&self) -> Vec<&Path> {
        self.repos.iter().map(|r| r.path.as_path()).collect()
    }
}

/// `~/.kin/registry.toml` path (cross-platform).
pub fn registry_path() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kin")
        .join("registry.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_load_save() {
        let dir = tempfile::tempdir().unwrap();
        let reg_path = dir.path().join("registry.toml");

        let mut reg = KinRegistry::default();
        reg.upsert("my-repo".to_string(), PathBuf::from("/tmp/my-repo"), 42);

        reg.save_to(&reg_path).unwrap();
        let loaded = KinRegistry::load_from(&reg_path).unwrap();

        assert_eq!(loaded.repos.len(), 1);
        assert_eq!(loaded.repos[0].id, "my-repo");
        assert_eq!(loaded.repos[0].path, PathBuf::from("/tmp/my-repo"));
        assert_eq!(loaded.repos[0].entities, 42);
        assert!(!loaded.repos[0].last_commit.is_empty());
    }

    #[test]
    fn upsert_updates_existing_entry() {
        let mut reg = KinRegistry::default();
        reg.upsert("repo".to_string(), PathBuf::from("/a"), 10);
        reg.upsert("repo".to_string(), PathBuf::from("/b"), 20);

        assert_eq!(reg.repos.len(), 1);
        assert_eq!(reg.repos[0].path, PathBuf::from("/b"));
        assert_eq!(reg.repos[0].entities, 20);
    }

    #[test]
    fn upsert_adds_distinct_repos() {
        let mut reg = KinRegistry::default();
        reg.upsert("repo-a".to_string(), PathBuf::from("/a"), 1);
        reg.upsert("repo-b".to_string(), PathBuf::from("/b"), 2);

        assert_eq!(reg.repos.len(), 2);
    }

    #[test]
    fn clean_removes_stale_paths() {
        let dir = tempfile::tempdir().unwrap();
        let valid_repo = dir.path().join("valid");
        std::fs::create_dir_all(valid_repo.join(".kin")).unwrap();

        let mut reg = KinRegistry::default();
        reg.upsert("valid".to_string(), valid_repo.clone(), 10);
        reg.upsert("stale".to_string(), PathBuf::from("/nonexistent/path"), 5);

        let removed = reg.clean();
        assert_eq!(removed, 1);
        assert_eq!(reg.repos.len(), 1);
        assert_eq!(reg.repos[0].id, "valid");
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let reg_path = dir.path().join("does-not-exist.toml");
        let reg = KinRegistry::load_from(&reg_path).unwrap();
        assert!(reg.repos.is_empty());
    }

    #[test]
    fn repo_paths_returns_all_paths() {
        let mut reg = KinRegistry::default();
        reg.upsert("a".to_string(), PathBuf::from("/a"), 1);
        reg.upsert("b".to_string(), PathBuf::from("/b"), 2);

        let paths = reg.repo_paths();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&Path::new("/a")));
        assert!(paths.contains(&Path::new("/b")));
    }
}
