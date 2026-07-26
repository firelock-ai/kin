// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

use tracing::{debug, info};

use kin_model::graph::GraphStore;
use kin_model::ids::EntityId;
use kin_model::verification::VerificationRun;
use kin_model::work::WorkId;

use crate::error::{Result, RuntimeError};

/// Strategy for materializing workspace files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializeStrategy {
    /// Copy-on-write reflink (fastest, CoW). Falls back to copy if unsupported.
    Reflink,
    /// Hard links (fast, shared inodes). Falls back to copy on failure.
    Hardlink,
    /// Full byte copy (slowest, always works).
    Copy,
}

impl std::fmt::Display for MaterializeStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reflink => write!(f, "reflink"),
            Self::Hardlink => write!(f, "hardlink"),
            Self::Copy => write!(f, "copy"),
        }
    }
}

impl std::str::FromStr for MaterializeStrategy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "reflink" => Ok(Self::Reflink),
            "hardlink" => Ok(Self::Hardlink),
            "copy" => Ok(Self::Copy),
            other => Err(format!(
                "unknown strategy: {other} (expected reflink, hardlink, or copy)"
            )),
        }
    }
}

/// A materialized workspace — a directory containing a copy of source files,
/// ready for command execution.
#[derive(Debug)]
pub struct MaterializedWorkspace {
    /// Root path of the materialized workspace.
    pub root: PathBuf,
    /// Strategy that was actually used.
    pub strategy: MaterializeStrategy,
    /// Which runtime-owned source path produced this workspace.
    source_kind: MaterializationSourceKind,
}

/// Which runtime-owned source path materialized the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationSourceKind {
    Filesystem,
    ExactTree,
}

/// Directories to skip when materializing the workspace.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    "vendor",
    ".kin",
];

impl MaterializedWorkspace {
    /// Create a materialized workspace by copying files from `source` to `target`.
    ///
    /// If `strategy` is `None`, tries reflink first, then hardlink, then copy.
    /// If a specific strategy is given, uses that (falling back to copy on failure).
    ///
    /// `scope` filters which files are materialized:
    /// - `None` — materialize everything
    /// - `Some("file:path/to/file")` — only materialize that specific file
    /// - `Some("path/to/file")` (bare path) — treated as file scope
    /// - `Some("entity:...")` — logs a notice and falls back to full materialization
    pub fn create(
        source: &Path,
        target: &Path,
        strategy: Option<MaterializeStrategy>,
        scope: Option<&str>,
    ) -> Result<Self> {
        if !source.exists() {
            return Err(RuntimeError::WorkspaceNotFound(
                source.display().to_string(),
            ));
        }

        std::fs::create_dir_all(target).map_err(|e| RuntimeError::io(target, e))?;

        let scope_filter = scope_filter_from_scope(scope);

        let used_strategy = match strategy {
            Some(s) => {
                materialize_with_strategy(source, target, s, scope_filter.as_deref())?;
                s
            }
            None => materialize_auto(source, target, scope_filter.as_deref())?,
        };

        info!(
            source = %source.display(),
            target = %target.display(),
            strategy = %used_strategy,
            "materialized workspace"
        );

        Ok(Self {
            root: target.to_path_buf(),
            strategy: used_strategy,
            source_kind: MaterializationSourceKind::Filesystem,
        })
    }

    /// Remove the materialized workspace directory.
    pub fn cleanup(&self) -> Result<()> {
        if self.root.exists() {
            std::fs::remove_dir_all(&self.root).map_err(|e| RuntimeError::io(&self.root, e))?;
            info!(path = %self.root.display(), "cleaned up materialized workspace");
        }
        Ok(())
    }

    /// Return which runtime-owned source path produced this workspace.
    pub fn source_kind(&self) -> MaterializationSourceKind {
        self.source_kind
    }

    /// Reconstruct a materialized workspace handle for a directory already
    /// created by another runtime boundary.
    pub fn from_existing(
        root: PathBuf,
        strategy: MaterializeStrategy,
        source_kind: MaterializationSourceKind,
    ) -> Self {
        Self {
            root,
            strategy,
            source_kind,
        }
    }
}

fn scope_filter_from_scope(scope: Option<&str>) -> Option<PathBuf> {
    match scope {
        Some(s) if s.starts_with("file:") => Some(PathBuf::from(s.strip_prefix("file:").unwrap())),
        Some(s) if s.starts_with("entity:") => {
            info!(scope = %s, "entity-scoped materialization is planned; falling back to full materialization");
            None
        }
        Some(s) => Some(PathBuf::from(s)),
        None => None,
    }
}

/// Try strategies in order: reflink -> hardlink -> copy.
fn materialize_auto(
    source: &Path,
    target: &Path,
    scope_filter: Option<&Path>,
) -> Result<MaterializeStrategy> {
    // Try reflink (fs::copy on CoW filesystems may use reflink automatically)
    match materialize_with_strategy(source, target, MaterializeStrategy::Reflink, scope_filter) {
        Ok(()) => return Ok(MaterializeStrategy::Reflink),
        Err(_) => {
            debug!("reflink failed, trying hardlink");
            // Clean up partial results
            clean_target_contents(target);
        }
    }

    // Try hardlink
    match materialize_with_strategy(source, target, MaterializeStrategy::Hardlink, scope_filter) {
        Ok(()) => return Ok(MaterializeStrategy::Hardlink),
        Err(_) => {
            debug!("hardlink failed, falling back to copy");
            clean_target_contents(target);
        }
    }

    // Copy always works
    materialize_with_strategy(source, target, MaterializeStrategy::Copy, scope_filter)?;
    Ok(MaterializeStrategy::Copy)
}

fn clean_target_contents(target: &Path) {
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(&path);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

fn materialize_with_strategy(
    source: &Path,
    target: &Path,
    strategy: MaterializeStrategy,
    scope_filter: Option<&Path>,
) -> Result<()> {
    materialize_dir_recursive(source, target, source, strategy, scope_filter)
}

fn materialize_dir_recursive(
    src: &Path,
    dst: &Path,
    root: &Path,
    strategy: MaterializeStrategy,
    scope_filter: Option<&Path>,
) -> Result<()> {
    for entry in std::fs::read_dir(src).map_err(|e| RuntimeError::io(src, e))? {
        let entry = entry.map_err(|e| RuntimeError::io(src, e))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only skip .git and .kin among hidden entries; allow .env, .cargo/, etc.
        if name_str.starts_with('.') && (name_str == ".git" || name_str == ".kin") {
            continue;
        }
        if SKIP_DIRS.contains(&name_str.as_ref()) {
            continue;
        }

        let src_path = entry.path();
        let dst_path = dst.join(&name);

        if src_path.is_dir() {
            // When scope_filter is active, only descend into directories
            // that are prefixes of the scoped file path.
            if let Some(filter) = scope_filter {
                let rel = src_path.strip_prefix(root).unwrap_or(&src_path);
                if !filter.starts_with(rel) {
                    continue;
                }
            }
            std::fs::create_dir_all(&dst_path).map_err(|e| RuntimeError::io(&dst_path, e))?;
            materialize_dir_recursive(&src_path, &dst_path, root, strategy, scope_filter)?;
        } else if src_path.is_file() {
            // When scope_filter is active, only copy the exact matching file.
            if let Some(filter) = scope_filter {
                let rel = src_path.strip_prefix(root).unwrap_or(&src_path);
                if rel != filter {
                    continue;
                }
            }
            match strategy {
                MaterializeStrategy::Reflink | MaterializeStrategy::Copy => {
                    // fs::copy uses copy-on-write on supported filesystems (APFS, btrfs)
                    std::fs::copy(&src_path, &dst_path)
                        .map_err(|e| RuntimeError::io(&src_path, e))?;
                }
                MaterializeStrategy::Hardlink => {
                    std::fs::hard_link(&src_path, &dst_path)
                        .map_err(|e| RuntimeError::io(&src_path, e))?;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Evidence capture wiring
// ---------------------------------------------------------------------------

/// Record a verification run's evidence in the graph store.
///
/// Called after test execution to link the run to proved entities and work items.
/// This is a thin orchestration function — the heavy lifting is done by the
/// `GraphStore` methods that were implemented in Phase 9/10.
pub fn record_verification_evidence<G: GraphStore>(
    graph: &G,
    run: &VerificationRun,
    proved_entities: &[EntityId],
    proved_work_items: &[WorkId],
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    graph.create_verification_run(run)?;
    for eid in proved_entities {
        graph.link_run_proves_entity(&run.run_id, eid)?;
    }
    for wid in proved_work_items {
        graph.link_run_proves_work(&run.run_id, wid)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ---- MaterializedWorkspace tests ----

    #[test]
    fn materialize_copy_creates_files() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::write(src.path().join("hello.txt"), "hi").unwrap();
        let sub = src.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("nested.txt"), "deep").unwrap();

        let mw = MaterializedWorkspace::create(
            src.path(),
            dst.path(),
            Some(MaterializeStrategy::Copy),
            None,
        )
        .unwrap();

        assert_eq!(mw.strategy, MaterializeStrategy::Copy);
        assert!(dst.path().join("hello.txt").exists());
        assert!(dst.path().join("sub").join("nested.txt").exists());
        assert_eq!(
            fs::read_to_string(dst.path().join("hello.txt")).unwrap(),
            "hi"
        );
    }

    #[test]
    fn materialize_skips_git_kin_and_large_dirs() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::write(src.path().join("keep.txt"), "yes").unwrap();

        // .git and .kin should still be skipped
        let git_dir = src.path().join(".git");
        fs::create_dir(&git_dir).unwrap();
        fs::write(git_dir.join("HEAD"), "ref: refs/heads/main").unwrap();

        let kin_dir = src.path().join(".kin");
        fs::create_dir(&kin_dir).unwrap();
        fs::write(kin_dir.join("config"), "data").unwrap();

        let nm = src.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("pkg.js"), "nope").unwrap();

        let target_dir = src.path().join("target");
        fs::create_dir(&target_dir).unwrap();
        fs::write(target_dir.join("binary"), "nope").unwrap();

        MaterializedWorkspace::create(
            src.path(),
            dst.path(),
            Some(MaterializeStrategy::Copy),
            None,
        )
        .unwrap();

        assert!(dst.path().join("keep.txt").exists());
        assert!(!dst.path().join(".git").exists());
        assert!(!dst.path().join(".kin").exists());
        assert!(!dst.path().join("node_modules").exists());
        assert!(!dst.path().join("target").exists());
    }

    #[test]
    fn materialize_includes_dotenv_and_cargo() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::write(src.path().join("keep.txt"), "yes").unwrap();

        // .env file should be materialized
        fs::write(src.path().join(".env"), "SECRET=123").unwrap();

        // .cargo/ directory should be materialized
        let cargo_dir = src.path().join(".cargo");
        fs::create_dir(&cargo_dir).unwrap();
        fs::write(
            cargo_dir.join("config.toml"),
            "[build]\ntarget-dir = \"target\"",
        )
        .unwrap();

        // .python-version should be materialized
        fs::write(src.path().join(".python-version"), "3.11").unwrap();

        // .npmrc should be materialized
        fs::write(
            src.path().join(".npmrc"),
            "registry=https://registry.npmjs.org/",
        )
        .unwrap();

        // .tool-versions should be materialized
        fs::write(src.path().join(".tool-versions"), "nodejs 20.0.0").unwrap();

        MaterializedWorkspace::create(
            src.path(),
            dst.path(),
            Some(MaterializeStrategy::Copy),
            None,
        )
        .unwrap();

        assert!(dst.path().join("keep.txt").exists());
        assert!(dst.path().join(".env").exists());
        assert_eq!(
            fs::read_to_string(dst.path().join(".env")).unwrap(),
            "SECRET=123"
        );
        assert!(dst.path().join(".cargo").join("config.toml").exists());
        assert!(dst.path().join(".python-version").exists());
        assert!(dst.path().join(".npmrc").exists());
        assert!(dst.path().join(".tool-versions").exists());
    }

    #[test]
    fn materialize_cleanup_removes_directory() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("file.txt"), "data").unwrap();

        let dst_root = tempfile::tempdir().unwrap();
        let dst = dst_root.path().join("workspace");
        fs::create_dir(&dst).unwrap();

        let mw =
            MaterializedWorkspace::create(src.path(), &dst, Some(MaterializeStrategy::Copy), None)
                .unwrap();

        assert!(dst.exists());
        mw.cleanup().unwrap();
        assert!(!dst.exists());
    }

    #[test]
    fn materialize_hardlink_creates_files() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::write(src.path().join("data.txt"), "linked").unwrap();

        let mw = MaterializedWorkspace::create(
            src.path(),
            dst.path(),
            Some(MaterializeStrategy::Hardlink),
            None,
        )
        .unwrap();

        assert_eq!(mw.strategy, MaterializeStrategy::Hardlink);
        assert_eq!(
            fs::read_to_string(dst.path().join("data.txt")).unwrap(),
            "linked"
        );
    }

    #[test]
    fn materialize_auto_succeeds() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::write(src.path().join("auto.txt"), "auto-test").unwrap();

        let mw = MaterializedWorkspace::create(src.path(), dst.path(), None, None).unwrap();

        // Should succeed with some strategy
        assert!(dst.path().join("auto.txt").exists());
        assert_eq!(
            fs::read_to_string(dst.path().join("auto.txt")).unwrap(),
            "auto-test"
        );
        // Strategy should be one of the valid values
        assert!(
            mw.strategy == MaterializeStrategy::Reflink
                || mw.strategy == MaterializeStrategy::Hardlink
                || mw.strategy == MaterializeStrategy::Copy
        );
    }

    #[test]
    fn materialize_missing_source_fails() {
        let dst = tempfile::tempdir().unwrap();
        let err = MaterializedWorkspace::create(
            Path::new("/nonexistent/source/xyz"),
            dst.path(),
            Some(MaterializeStrategy::Copy),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, RuntimeError::WorkspaceNotFound(_)));
    }

    #[test]
    fn materialize_strategy_from_str() {
        assert_eq!(
            "reflink".parse::<MaterializeStrategy>().unwrap(),
            MaterializeStrategy::Reflink
        );
        assert_eq!(
            "hardlink".parse::<MaterializeStrategy>().unwrap(),
            MaterializeStrategy::Hardlink
        );
        assert_eq!(
            "copy".parse::<MaterializeStrategy>().unwrap(),
            MaterializeStrategy::Copy
        );
        assert!("unknown".parse::<MaterializeStrategy>().is_err());
    }
}
