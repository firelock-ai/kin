// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use tracing::info;

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
    ExactTree,
}

impl MaterializedWorkspace {
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

    #[test]
    fn exact_materialization_handle_cleans_up_its_directory() {
        let dst_root = tempfile::tempdir().unwrap();
        let dst = dst_root.path().join("workspace");
        std::fs::create_dir(&dst).unwrap();
        std::fs::write(dst.join("file.txt"), b"data").unwrap();
        let workspace = MaterializedWorkspace::from_existing(
            dst.clone(),
            MaterializeStrategy::Copy,
            MaterializationSourceKind::ExactTree,
        );

        assert!(dst.exists());
        workspace.cleanup().unwrap();
        assert!(!dst.exists());
    }

    #[test]
    fn materialization_strategy_from_str() {
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
