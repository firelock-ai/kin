// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scanner::RepoScan;

/// Migration strategy: controls how much history is imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum MigrationStrategy {
    /// Import only HEAD (current tree state). Fast (<15s target).
    /// Creates a single SemanticChange from the working tree.
    #[default]
    Shallow,
    /// Import full Git history. Walks all reachable commits and
    /// converts each into a SemanticChange with proper DAG links.
    Deep,
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
    /// Maximum commits to import in Deep mode (0 = unlimited).
    pub max_commits: usize,
    /// Source files to index for entity extraction.
    pub source_files: Vec<PathBuf>,
}

/// Plan a migration based on scan results and user preferences.
pub fn plan_migration(
    scan: &RepoScan,
    strategy: MigrationStrategy,
    target: Option<PathBuf>,
    max_commits: usize,
) -> MigrationPlan {
    let target_dir = target.unwrap_or_else(|| scan.root.clone());

    MigrationPlan {
        source: scan.root.clone(),
        target: target_dir,
        strategy,
        branch: scan.default_branch.clone(),
        max_commits,
        source_files: scan.source_files.clone(),
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
        writeln!(out, "  Source files: {}", self.source_files.len()).unwrap();
        if self.strategy == MigrationStrategy::Deep && self.max_commits > 0 {
            writeln!(out, "  Max commits: {}", self.max_commits).unwrap();
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
            commit_count: 100,
            branches: vec!["main".into()],
            source_files: vec![PathBuf::from("src/lib.rs"), PathBuf::from("src/main.rs")],
        }
    }

    #[test]
    fn plan_shallow_migration() {
        let scan = make_scan();
        let plan = plan_migration(&scan, MigrationStrategy::Shallow, None, 0);
        assert_eq!(plan.strategy, MigrationStrategy::Shallow);
        assert_eq!(plan.source, PathBuf::from("/project"));
        assert_eq!(plan.target, PathBuf::from("/project"));
        assert_eq!(plan.source_files.len(), 2);
    }

    #[test]
    fn plan_deep_migration_with_target() {
        let scan = make_scan();
        let plan = plan_migration(
            &scan,
            MigrationStrategy::Deep,
            Some(PathBuf::from("/output")),
            50,
        );
        assert_eq!(plan.strategy, MigrationStrategy::Deep);
        assert_eq!(plan.target, PathBuf::from("/output"));
        assert_eq!(plan.max_commits, 50);
    }

    #[test]
    fn default_strategy_is_shallow() {
        assert_eq!(MigrationStrategy::default(), MigrationStrategy::Shallow);
    }

    #[test]
    fn plan_describe_output() {
        let scan = make_scan();
        let plan = plan_migration(&scan, MigrationStrategy::Deep, None, 25);
        let desc = plan.describe();
        assert!(desc.contains("Deep"));
        assert!(desc.contains("Max commits: 25"));
        assert!(desc.contains("Source files: 2"));
    }

    #[test]
    fn strategy_serializes() {
        let json = serde_json::to_string(&MigrationStrategy::Shallow).unwrap();
        let parsed: MigrationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MigrationStrategy::Shallow);
    }
}
