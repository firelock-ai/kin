// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scanner::RepoScan;

/// Migration strategy: controls how much history is imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStrategy {
    /// Import an exact current-tree snapshot without claiming ancestry.
    #[default]
    Snapshot,
    /// Import every reachable Git commit and exact parent edge.
    Full,
}

/// Configuration for a migration operation.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    /// Source Git repository path.
    pub source: PathBuf,
    /// Target directory for the Kin repo (defaults to source).
    pub target: PathBuf,
    /// Migration strategy.
    pub strategy: MigrationStrategy,
    /// Branch to import (None = HEAD / default branch).
    pub branch: Option<String>,
}

/// Plan a migration based on scan results and user preferences.
pub fn plan_migration(
    scan: &RepoScan,
    strategy: MigrationStrategy,
    target: Option<PathBuf>,
) -> MigrationPlan {
    let target_dir = target.unwrap_or_else(|| scan.root.clone());

    MigrationPlan {
        source: scan.root.clone(),
        target: target_dir,
        strategy,
        branch: scan.default_branch.clone(),
    }
}

impl MigrationPlan {
    /// Describe the plan in human-readable form.
    pub fn describe(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        writeln!(out, "Migration Plan:").unwrap();
        writeln!(out, "  Source: {}", self.source.display()).unwrap();
        writeln!(out, "  Target: {}", self.target.display()).unwrap();
        writeln!(out, "  Strategy: {:?}", self.strategy).unwrap();
        if let Some(ref branch) = self.branch {
            writeln!(out, "  Branch: {}", branch).unwrap();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scan() -> RepoScan {
        RepoScan {
            root: PathBuf::from("/project"),
            default_branch: Some("main".into()),
        }
    }

    #[test]
    fn plan_snapshot_migration() {
        let scan = make_scan();
        let plan = plan_migration(&scan, MigrationStrategy::Snapshot, None);
        assert_eq!(plan.strategy, MigrationStrategy::Snapshot);
        assert_eq!(plan.source, PathBuf::from("/project"));
        assert_eq!(plan.target, PathBuf::from("/project"));
    }

    #[test]
    fn plan_full_migration_with_target() {
        let scan = make_scan();
        let plan = plan_migration(
            &scan,
            MigrationStrategy::Full,
            Some(PathBuf::from("/output")),
        );
        assert_eq!(plan.strategy, MigrationStrategy::Full);
        assert_eq!(plan.target, PathBuf::from("/output"));
    }

    #[test]
    fn default_strategy_is_snapshot() {
        assert_eq!(MigrationStrategy::default(), MigrationStrategy::Snapshot);
    }

    #[test]
    fn plan_describe_output() {
        let scan = make_scan();
        let plan = plan_migration(&scan, MigrationStrategy::Full, None);
        let desc = plan.describe();
        assert!(desc.contains("Full"));
        assert!(!desc.contains("Source files"));
    }

    #[test]
    fn strategy_serializes() {
        let json = serde_json::to_string(&MigrationStrategy::Snapshot).unwrap();
        let parsed: MigrationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MigrationStrategy::Snapshot);
    }
}
