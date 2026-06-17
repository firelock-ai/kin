// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

use crate::error::KinError;

/// Current `.kin/` directory schema version.
///
/// Bump this when the layout changes in a way that requires migration.
pub const KIN_LAYOUT_VERSION: u32 = 1;

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
    /// Returns `None` if no `.kin/` directory is found. The global home
    /// `~/.kin` is the cross-repo registry/cache root, not a servable repo: it
    /// holds `registry.toml` but never a `manifest.json`. Discovery skips it so
    /// running outside any repo does not resolve to the home directory and spawn
    /// a daemon that fails `resolve_repo_id` against a non-existent manifest.
    pub fn discover(start: &Path) -> Option<Self> {
        if std::env::var("KIN_DAEMON_URL").is_ok() {
            return Some(Self::new(start.join(".kin")));
        }
        let mut current = start.to_path_buf();
        loop {
            let candidate = current.join(".kin");
            if candidate.is_dir() && !is_global_home_kin_dir(&candidate) {
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

    /// `.kin/kindb/graph.kvec` — persisted vector index aligned with the snapshot.
    pub fn kindb_vector_index_path(&self) -> PathBuf {
        self.kindb_snapshot_path().with_extension("kvec")
    }

    /// `.kin/kindb/text-index/` — Persistent tantivy text index directory.
    pub fn text_index_dir(&self) -> PathBuf {
        self.kindb_dir().join("text-index")
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

    /// `.kin/version` — layout schema version marker.
    pub fn version_path(&self) -> PathBuf {
        self.root.join("version")
    }

    /// Read the schema version from the `.kin/version` file.
    ///
    /// Returns `KIN_LAYOUT_VERSION` if the file does not exist (pre-versioning repos).
    pub fn read_version(&self) -> Result<u32, KinError> {
        let path = self.version_path();
        if !path.exists() {
            // Pre-versioning repo — treat as version 1 (current).
            return Ok(KIN_LAYOUT_VERSION);
        }
        let text = std::fs::read_to_string(&path).map_err(|e| KinError::io(&path, e))?;
        text.trim().parse::<u32>().map_err(|_| {
            KinError::Config(format!("invalid version in {}: {text:?}", path.display()))
        })
    }

    /// Verify that this binary can read the `.kin/` directory.
    ///
    /// Returns an error if the on-disk version is newer than what we support.
    pub fn check_version(&self) -> Result<(), KinError> {
        let current = self.read_version()?;
        if current > KIN_LAYOUT_VERSION {
            return Err(KinError::IncompatibleVersion {
                found: current,
                supported: KIN_LAYOUT_VERSION,
            });
        }
        Ok(())
    }

    /// Write the `.kin/version` marker, stamping the layout at `version`.
    fn write_version(&self, version: u32) -> Result<(), KinError> {
        let path = self.version_path();
        std::fs::write(&path, version.to_string()).map_err(|e| KinError::io(&path, e))
    }

    /// Bring the on-disk `.kin/` layout up to the version this binary writes.
    ///
    /// This is never a silent no-op:
    /// - a newer-than-supported layout is refused with [`KinError::IncompatibleVersion`];
    /// - a pre-versioning repo (no `.kin/version`) is stamped at the current
    ///   version — a real, idempotent action, since the first version is layout-
    ///   compatible with an unmarked tree;
    /// - an older layout is walked forward one step at a time via [`Self::migrate_step`],
    ///   which transforms `v -> v+1` on disk or **loudly refuses** when no step is
    ///   registered for that version. An older layout is never accepted as-is.
    ///
    /// When the on-disk version already equals [`KIN_LAYOUT_VERSION`] there is
    /// genuinely nothing to do and `Ok(())` is returned without touching disk.
    pub fn migrate(&self) -> Result<(), KinError> {
        // A pre-versioning repo predates the marker entirely. `read_version`
        // maps a missing file onto the current version, so detect absence
        // directly and stamp the tree forward rather than assuming it.
        if !self.version_path().exists() {
            self.write_version(KIN_LAYOUT_VERSION)?;
            return Ok(());
        }

        let mut current = self.read_version()?;
        if current > KIN_LAYOUT_VERSION {
            return Err(KinError::IncompatibleVersion {
                found: current,
                supported: KIN_LAYOUT_VERSION,
            });
        }

        while current < KIN_LAYOUT_VERSION {
            self.migrate_step(current)?;
            current += 1;
            self.write_version(current)?;
        }
        Ok(())
    }

    /// Apply the single migration that upgrades the on-disk layout from `from`
    /// to `from + 1`.
    ///
    /// Each future breaking layout change registers its step in the `match`
    /// below (e.g. `1 => self.migrate_v1_to_v2(),`). A version with no
    /// registered step is refused loudly rather than skipped, so an old `.kin/`
    /// can never be served against a binary that does not know how to upgrade
    /// it.
    fn migrate_step(&self, from: u32) -> Result<(), KinError> {
        match from {
            // Register future migration steps here, lowest version first.
            other => Err(KinError::Config(format!(
                "no migration path for .kin/ layout version {other} -> {next}: \
                 this repository predates a breaking layout change that this kin \
                 build cannot auto-upgrade. Re-run `kin init` in a fresh checkout \
                 or restore from a backup made with a matching kin version.",
                next = other + 1,
            ))),
        }
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

/// The global home Kin directory `~/.kin` — the cross-repo registry/cache root,
/// not a servable repo. Returns `None` when no home directory is resolvable.
pub fn global_home_kin_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".kin"))
}

/// Whether `candidate` is the global home `~/.kin` registry/cache root rather
/// than a real repository. The home root holds `registry.toml` but never a
/// `manifest.json`; a candidate that carries a manifest is a real repo even if
/// it happens to live at `~/.kin`, so it is not treated as the home root.
fn is_global_home_kin_dir(candidate: &Path) -> bool {
    let Some(home_kin) = global_home_kin_dir() else {
        return false;
    };
    if candidate != home_kin {
        // Compare canonical forms too, so symlinked or non-normalized paths
        // (e.g. a `/var` vs `/private/var` HOME on macOS) still match.
        let canonical_candidate = candidate.canonicalize().ok();
        let canonical_home = home_kin.canonicalize().ok();
        match (canonical_candidate, canonical_home) {
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
    !candidate.join("manifest.json").exists()
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

    #[test]
    fn is_global_home_kin_dir_rejects_unrelated_and_repo_paths() {
        // A normal repo `.kin` (carrying a manifest) is never the home root.
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("manifest.json"), "{}").unwrap();
        assert!(!is_global_home_kin_dir(&kin_dir));

        // An unrelated `.kin` path that is not the home root is never the home
        // root either, regardless of manifest presence.
        let bare = dir.path().join("sub").join(".kin");
        std::fs::create_dir_all(&bare).unwrap();
        assert!(!is_global_home_kin_dir(&bare));
    }

    #[test]
    fn global_home_kin_dir_targets_home_dot_kin() {
        if let Some(home_kin) = global_home_kin_dir() {
            assert_eq!(home_kin.file_name().and_then(|n| n.to_str()), Some(".kin"));
        }
    }

    fn empty_kin_layout() -> (tempfile::TempDir, KinLayout) {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);
        (dir, layout)
    }

    #[test]
    fn migrate_stamps_pre_versioning_repo() {
        let (_dir, layout) = empty_kin_layout();
        assert!(!layout.version_path().exists());
        layout.migrate().unwrap();
        let stamped = std::fs::read_to_string(layout.version_path()).unwrap();
        assert_eq!(stamped.trim(), KIN_LAYOUT_VERSION.to_string());
    }

    #[test]
    fn migrate_is_noop_on_current_version() {
        let (_dir, layout) = empty_kin_layout();
        layout.write_version(KIN_LAYOUT_VERSION).unwrap();
        let before = std::fs::metadata(layout.version_path())
            .unwrap()
            .modified()
            .unwrap();
        layout.migrate().unwrap();
        // Current version: nothing rewritten.
        let after = std::fs::metadata(layout.version_path())
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn migrate_refuses_newer_layout() {
        let (_dir, layout) = empty_kin_layout();
        layout.write_version(KIN_LAYOUT_VERSION + 7).unwrap();
        match layout.migrate() {
            Err(KinError::IncompatibleVersion { found, supported }) => {
                assert_eq!(found, KIN_LAYOUT_VERSION + 7);
                assert_eq!(supported, KIN_LAYOUT_VERSION);
            }
            other => panic!("expected IncompatibleVersion, got {other:?}"),
        }
    }

    #[test]
    fn migrate_loudly_refuses_old_unmigratable_layout() {
        // Synthesize an older layout (version 0) with no registered upgrade
        // step. migrate() must refuse loudly, never silently accept it.
        let (_dir, layout) = empty_kin_layout();
        layout.write_version(0).unwrap();
        match layout.migrate() {
            Err(KinError::Config(msg)) => {
                assert!(msg.contains("no migration path"), "got: {msg}");
            }
            other => panic!("expected loud Config refusal, got {other:?}"),
        }
        // The on-disk version is left untouched by a refused migration.
        assert_eq!(layout.read_version().unwrap(), 0);
    }
}
