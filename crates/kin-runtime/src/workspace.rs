// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::graph::GraphStore;
use kin_model::ids::EntityId;
use kin_model::verification::VerificationRun;
use kin_model::work::WorkId;

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
    projection: kin_core::ExactSessionProjection,
    strategy: MaterializeStrategy,
}

/// Which runtime-owned source path materialized the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationSourceKind {
    ExactTree,
}

impl MaterializedWorkspace {
    /// Construct a runtime handle from Kin's opaque authority-issued session
    /// projection. Arbitrary ambient paths cannot be promoted to this type.
    pub fn from_exact_session(
        projection: kin_core::ExactSessionProjection,
        strategy: MaterializeStrategy,
    ) -> Self {
        Self {
            projection,
            strategy,
        }
    }

    /// Root of the retained exact session projection.
    pub fn root(&self) -> &std::path::Path {
        self.projection.root()
    }

    /// Materialization strategy used for this exact session.
    pub fn strategy(&self) -> MaterializeStrategy {
        self.strategy
    }

    /// Revalidate the authority-bearing projection before a runtime consumer
    /// relies on its ambient display path.
    pub fn revalidate(&self) -> kin_core::Result<()> {
        self.projection.revalidate()
    }

    /// Return which runtime-owned source path produced this workspace.
    pub fn source_kind(&self) -> MaterializationSourceKind {
        MaterializationSourceKind::ExactTree
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
    fn exact_materialization_handle_requires_authority_issued_projection() {
        let repository = tempfile::tempdir().unwrap();
        kin_core::init(repository.path()).unwrap();
        let path = kin_model::RepoPath::from_utf8("compose.yaml").unwrap();
        let body = b"services: {}\n";
        let entry = kin_model::TreeEntry::blob(
            kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(body)),
            false,
        );
        let freeze = kin_core::ExactProjectionFreeze::acquire_existing(repository.path()).unwrap();
        let (projection, count) = freeze
            .materialize_session_source_tree(
                "session-runtime-handle",
                br#"{"schema":1}"#,
                [(&path, entry, body.as_slice())],
            )
            .unwrap();
        let workspace =
            MaterializedWorkspace::from_exact_session(projection, MaterializeStrategy::Copy);

        assert_eq!(count, 1);
        assert_eq!(workspace.strategy(), MaterializeStrategy::Copy);
        assert_eq!(
            workspace.source_kind(),
            MaterializationSourceKind::ExactTree
        );
        assert_eq!(
            std::fs::read(workspace.root().join("compose.yaml")).unwrap(),
            body
        );
        workspace.revalidate().unwrap();
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
