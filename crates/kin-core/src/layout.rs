// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

/// The `.kin/` directory layout.
///
/// All paths are computed lazily from a single `root` — the `.kin/` directory.
#[derive(Debug, Clone)]
pub struct KinLayout {
    root: PathBuf,
}

impl KinLayout {
    /// Create a layout rooted at the given `.kin/` directory.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Discover the `.kin/` directory by walking up from `start`.
    ///
    /// Returns `None` if no `.kin/` directory is found.
    pub fn discover(start: &Path) -> Option<Self> {
        let mut current = start.to_path_buf();
        loop {
            let candidate = current.join(".kin");
            if candidate.is_dir() {
                return Some(Self::new(candidate));
            }
            if !current.pop() {
                return None;
            }
        }
    }

    /// The `.kin/` root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The working directory (parent of `.kin/`).
    pub fn working_dir(&self) -> &Path {
        self.root
            .parent()
            .expect(".kin/ always has a parent directory")
    }

    /// `.kin/config.toml`
    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    /// `.kin/manifest.json`
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    /// `.kin/kindb/` — KinDB snapshot and index directory.
    pub fn kindb_dir(&self) -> PathBuf {
        self.root.join("kindb")
    }

    /// `.kin/kindb/graph.kndb` — KinDB snapshot file.
    pub fn kindb_snapshot_path(&self) -> PathBuf {
        self.kindb_dir().join("graph.kndb")
    }

    /// `.kin/objects/` — Content-addressable blob store.
    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    /// `.kin/stashes/` — Named overlay snapshots.
    pub fn stashes_dir(&self) -> PathBuf {
        self.root.join("stashes")
    }

    /// `.kin/backups/` — Graph snapshot backups.
    pub fn backups_dir(&self) -> PathBuf {
        self.root.join("backups")
    }

    /// `.kin/projections/` — Generated file/doc projections.
    pub fn projections_dir(&self) -> PathBuf {
        self.root.join("projections")
    }

    /// `.kin/docs/` — Living docs (AGENTS.md, ARCHITECTURE.md, etc.).
    pub fn docs_dir(&self) -> PathBuf {
        self.root.join("docs")
    }

    /// `.kin/bench/` — Benchmark traces and reports.
    pub fn bench_dir(&self) -> PathBuf {
        self.root.join("bench")
    }

    /// `.kin/runs/` — Validation run evidence.
    pub fn runs_dir(&self) -> PathBuf {
        self.root.join("runs")
    }

    /// `.kin/logs/` — Daemon logs.
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// `.kin/adapters/` — Assistant adapter config.
    pub fn adapters_dir(&self) -> PathBuf {
        self.root.join("adapters")
    }

    /// `.kin/shallow/` — Persisted C2 shallow-syntax metadata.
    pub fn shallow_dir(&self) -> PathBuf {
        self.root.join("shallow")
    }

    /// `.kin/HEAD` — current branch pointer.
    pub fn head_path(&self) -> PathBuf {
        self.root.join("HEAD")
    }

    /// `.kin/source-root/` — source files in Kin-native mode.
    pub fn source_root_dir(&self) -> PathBuf {
        self.root.join("source-root")
    }

    /// `.kin/mode` — file containing `native` or `compat`.
    pub fn mode_path(&self) -> PathBuf {
        self.root.join("mode")
    }

    /// `.kin/sync_state.json` — persisted sync state per remote.
    pub fn sync_state_path(&self) -> PathBuf {
        self.root.join("sync_state.json")
    }

    /// `.kin/merge_state.json` — persisted merge conflict state.
    ///
    /// Written by `kin merge` when conflicts are detected, read by
    /// `kin conflicts` and `kin resolve`, cleared on resolution or abort.
    pub fn merge_state_path(&self) -> PathBuf {
        self.root.join("merge_state.json")
    }

    /// All directories that must exist inside `.kin/`.
    ///
    pub fn all_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.kindb_dir(),
            self.objects_dir(),
            self.stashes_dir(),
            self.backups_dir(),
            self.projections_dir(),
            self.docs_dir(),
            self.bench_dir(),
            self.runs_dir(),
            self.logs_dir(),
            self.adapters_dir(),
            self.shallow_dir(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_paths() {
        let layout = KinLayout::new(PathBuf::from("/repo/.kin"));
        assert_eq!(
            layout.config_path(),
            PathBuf::from("/repo/.kin/config.toml")
        );
        assert_eq!(
            layout.manifest_path(),
            PathBuf::from("/repo/.kin/manifest.json")
        );
        assert_eq!(layout.kindb_dir(), PathBuf::from("/repo/.kin/kindb"));
        assert_eq!(
            layout.kindb_snapshot_path(),
            PathBuf::from("/repo/.kin/kindb/graph.kndb")
        );
        assert_eq!(layout.objects_dir(), PathBuf::from("/repo/.kin/objects"));
        assert_eq!(layout.working_dir(), Path::new("/repo"));
    }

    #[test]
    fn all_dirs_count() {
        let layout = KinLayout::new(PathBuf::from("/repo/.kin"));
        // kindb, objects, stashes, backups, projections, docs, bench, runs, logs, adapters, shallow
        assert_eq!(layout.all_dirs().len(), 11);
    }

    #[test]
    fn discover_finds_kin_dir() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();

        let found = KinLayout::discover(dir.path()).unwrap();
        assert_eq!(found.root(), kin_dir);
    }

    #[test]
    fn discover_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        let sub = dir.path().join("src").join("deep");
        std::fs::create_dir_all(&sub).unwrap();

        let found = KinLayout::discover(&sub).unwrap();
        assert_eq!(found.root(), kin_dir);
    }

    #[test]
    fn discover_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(KinLayout::discover(dir.path()).is_none());
    }
}
